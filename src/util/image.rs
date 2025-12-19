use image::{DynamicImage, GenericImageView, ImageFormat, imageops::FilterType};
use std::io::Cursor;

use crate::error::AppError;

/// Avatar dimensions
const AVATAR_SIZE: u32 = 128;
/// Blurhash components
const BLURHASH_COMPONENTS_X: u32 = 4;
const BLURHASH_COMPONENTS_Y: u32 = 3;

/// Process an image to create an avatar and blurhash
pub fn to_avatar(photo_data: &[u8]) -> Result<(Vec<u8>, String), AppError> {
    // Load the image
    let img = image::load_from_memory(photo_data)
        .map_err(|e| AppError::InvalidArgument(format!("Failed to load image: {}", e)))?;

    // Create avatar (resized image)
    let avatar = create_avatar(&img)?;

    // Generate blurhash
    let blurhash = generate_blurhash(&img)?;

    Ok((avatar, blurhash))
}

/// Create a square avatar from an image
fn create_avatar(img: &DynamicImage) -> Result<Vec<u8>, AppError> {
    let (width, height) = img.dimensions();

    // Crop to square from center
    let size = width.min(height);
    let x = (width - size) / 2;
    let y = (height - size) / 2;

    let cropped = img.crop_imm(x, y, size, size);

    // Resize to avatar size
    let resized = cropped.resize_exact(AVATAR_SIZE, AVATAR_SIZE, FilterType::Lanczos3);

    // Encode as PNG
    let mut buffer = Vec::new();
    resized
        .write_to(&mut Cursor::new(&mut buffer), ImageFormat::Png)
        .map_err(|e| AppError::Internal(format!("Failed to encode avatar: {}", e)))?;

    Ok(buffer)
}

/// Generate a blurhash from an image
fn generate_blurhash(img: &DynamicImage) -> Result<String, AppError> {
    // Resize image for blurhash generation (smaller = faster)
    let small = img.resize(32, 32, FilterType::Triangle);
    let rgba = small.to_rgba8();
    let (width, height) = rgba.dimensions();

    let hash = blurhash::encode(
        BLURHASH_COMPONENTS_X,
        BLURHASH_COMPONENTS_Y,
        width,
        height,
        rgba.as_raw(),
    )
    .map_err(|e| AppError::Internal(format!("Failed to generate blurhash: {}", e)))?;

    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_avatar_and_blurhash() {
        // Create a simple test image
        let img = DynamicImage::new_rgb8(100, 100);
        let mut buffer = Vec::new();
        img.write_to(&mut Cursor::new(&mut buffer), ImageFormat::Png)
            .unwrap();

        let result = to_avatar(&buffer);
        assert!(result.is_ok());

        let (avatar, blurhash) = result.unwrap();
        assert!(!avatar.is_empty());
        assert!(!blurhash.is_empty());
    }
}
