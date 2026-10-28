//! A camera as a [`FrameSource`] (feature `camera`), through `nokhwa`:
//! AVFoundation on macOS, V4L2 on Linux, Media Foundation on Windows.
//!
//! Only uncompressed formats are requested (YUYV, NV12, grey, RGB, BGR):
//! decoding MJPEG would need `mozjpeg`, a C library. A camera that offers
//! nothing else is refused with that reason rather than failing on its
//! first frame.

use std::fmt;
use std::sync::mpsc;
use std::time::Duration;

use nokhwa::pixel_format::LumaFormat;
use nokhwa::utils::{ApiBackend, CameraIndex, FrameFormat, RequestedFormat, RequestedFormatType};

use crate::QrError;
use crate::scan::{FrameSource, LumaFrame};

const FORMATS: &[FrameFormat] = &[
    FrameFormat::YUYV,
    FrameFormat::NV12,
    FrameFormat::GRAY,
    FrameFormat::RAWRGB,
    FrameFormat::RAWBGR,
];

/// How long to wait for the user to answer macOS's camera permission
/// prompt.
const PERMISSION_WAIT: Duration = Duration::from_secs(60);

/// Why there is no camera to scan with.
#[derive(Debug, thiserror::Error)]
pub enum CameraError {
    #[error(
        "camera access is denied; grant it to this terminal application in System Settings > \
         Privacy & Security > Camera, or paste the frames instead"
    )]
    Denied,
    #[error("no camera found")]
    NotFound,
    #[error(
        "the camera offers only compressed (MJPEG) frames, which this build cannot decode; use \
         another camera, or paste the frames instead"
    )]
    OnlyMjpeg,
    #[error("the camera failed: {0}")]
    Failed(String),
}

/// Ask for camera access (a prompt on macOS the first time; a no-op
/// elsewhere) and wait for the answer.
fn authorize() -> Result<(), CameraError> {
    if nokhwa::nokhwa_check() {
        return Ok(());
    }
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    nokhwa::nokhwa_initialize(move |granted| {
        if let Ok(tx) = tx.lock() {
            let _ = tx.send(granted);
        }
    });
    match rx.recv_timeout(PERMISSION_WAIT) {
        Ok(true) => Ok(()),
        _ => Err(CameraError::Denied),
    }
}

/// An open camera.
pub struct Camera {
    inner: nokhwa::Camera,
}

impl fmt::Debug for Camera {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Camera")
            .field("name", &self.inner.info().human_name())
            .finish()
    }
}

impl Camera {
    /// Open camera `index` (the first when `None`) and start its stream.
    pub fn open(index: Option<u32>) -> Result<Self, CameraError> {
        // Look before asking: a machine without a camera fails at once
        // instead of waiting on a permission prompt.
        let cameras =
            nokhwa::query(ApiBackend::Auto).map_err(|e| CameraError::Failed(e.to_string()))?;
        if cameras.is_empty() {
            return Err(CameraError::NotFound);
        }
        authorize()?;
        let index = CameraIndex::Index(index.unwrap_or(0));
        let requested =
            RequestedFormat::with_formats(RequestedFormatType::AbsoluteHighestFrameRate, FORMATS);
        let mut inner = match nokhwa::Camera::new(index.clone(), requested) {
            Ok(c) => c,
            Err(e) => {
                // Tell an MJPEG-only camera apart from a missing one.
                let any = RequestedFormat::new::<LumaFormat>(
                    RequestedFormatType::AbsoluteHighestFrameRate,
                );
                return Err(match nokhwa::Camera::new(index, any) {
                    Ok(_) => CameraError::OnlyMjpeg,
                    Err(_) => CameraError::Failed(e.to_string()),
                });
            }
        };
        inner
            .open_stream()
            .map_err(|e| CameraError::Failed(e.to_string()))?;
        Ok(Self { inner })
    }

    /// The camera's name, for a status line.
    pub fn name(&self) -> String {
        self.inner.info().human_name()
    }
}

impl FrameSource for Camera {
    fn next_frame(&mut self) -> Result<LumaFrame, QrError> {
        let fail = |e: nokhwa::NokhwaError| QrError::Ur(format!("camera: {e}"));
        let buffer = self.inner.frame().map_err(fail)?;
        let image = buffer.decode_image::<LumaFormat>().map_err(fail)?;
        let (width, height) = (image.width() as usize, image.height() as usize);
        Ok(LumaFrame {
            width,
            height,
            data: image.into_raw(),
        })
    }
}

impl Drop for Camera {
    fn drop(&mut self) {
        let _ = self.inner.stop_stream();
    }
}
