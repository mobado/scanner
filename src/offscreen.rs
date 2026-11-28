//! Draws the window's content into a picture without a screen. `--screenshot` uses it when the
//! window itself cannot be painted: with the screen locked or the window never shown, the
//! compositor accepts no frames.

use eframe::egui;
use eframe::egui_wgpu::{Renderer, RendererOptions, ScreenDescriptor};
use eframe::wgpu;
use std::future::Future;
use std::path::Path;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

const FORMAT: wgpu::TextureFormat = wgpu::TextureFormat::Rgba8Unorm;
/// Frames to draw before the picture, so that sizes and scroll areas have settled.
const FRAMES: u32 = 30;
/// Longest wait for the content to be ready.
const PATIENCE: Duration = Duration::from_secs(40);

/// Wait for one of the graphics library's futures (they finish without an async runtime).
fn wait<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Draw `draw` (which returns true once its content is ready) at `size` points and save the
/// last frame as a PNG.
pub fn save_picture(
    ctx: &egui::Context,
    size: [u32; 2],
    background: egui::Color32,
    path: &Path,
    mut draw: impl FnMut(&mut egui::Ui) -> bool,
) -> Result<(), String> {
    let instance = wgpu::Instance::default();
    let adapter = wait(instance.request_adapter(&wgpu::RequestAdapterOptions::default())).map_err(|e| format!("no graphics adapter: {e}"))?;
    let descriptor = wgpu::DeviceDescriptor { required_limits: adapter.limits(), ..Default::default() };
    let (device, queue) = wait(adapter.request_device(&descriptor)).map_err(|e| format!("the graphics device could not start: {e}"))?;
    let mut renderer = Renderer::new(&device, FORMAT, RendererOptions::default());

    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(size[0] as f32, size[1] as f32));
    let start = Instant::now();
    let mut frames = 0u32;
    let mut settled = 0u32;
    let (shapes, pixels_per_point) = loop {
        let input = egui::RawInput {
            screen_rect: Some(screen),
            time: Some(f64::from(frames) / 30.0),
            max_texture_side: Some(device.limits().max_texture_dimension_2d as usize),
            ..Default::default()
        };
        let mut ready = false;
        let mut output = ctx.run_ui(input, |ui| ready = draw(ui));
        // fonts and images arrive as changes that must all be applied, in order
        for (id, deltas) in &output.textures_delta.set {
            for delta in deltas {
                renderer.update_texture(&device, &queue, *id, delta);
            }
        }
        frames += 1;
        settled = if ready { settled + 1 } else { 0 };
        let last = settled >= FRAMES || start.elapsed() > PATIENCE;
        if !last {
            // textures dropped by the last frame are still needed to draw it
            for id in &output.textures_delta.free {
                renderer.free_texture(id);
            }
        }
        // egui insists that every change is marked as handled
        output.textures_delta.clear();
        if last {
            break (output.shapes, output.pixels_per_point);
        }
        std::thread::sleep(Duration::from_millis(if ready { 5 } else { 100 }));
    };

    let paint_jobs = ctx.tessellate(shapes, pixels_per_point);
    let [width, height] = [(size[0] as f32 * pixels_per_point) as u32, (size[1] as f32 * pixels_per_point) as u32];
    let screen = ScreenDescriptor { size_in_pixels: [width, height], pixels_per_point };
    let extent = wgpu::Extent3d { width, height, depth_or_array_layers: 1 };
    let texture = device.create_texture(&wgpu::TextureDescriptor {
        label: Some("picture"),
        size: extent,
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format: FORMAT,
        usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
        view_formats: &[],
    });
    let view = texture.create_view(&Default::default());
    // rows in a buffer must start at a multiple of 256 bytes
    let row = width * 4;
    let padded = row.div_ceil(wgpu::COPY_BYTES_PER_ROW_ALIGNMENT) * wgpu::COPY_BYTES_PER_ROW_ALIGNMENT;
    let buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("picture pixels"),
        size: u64::from(padded) * u64::from(height),
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });
    let mut encoder = device.create_command_encoder(&Default::default());
    let extra = renderer.update_buffers(&device, &queue, &mut encoder, &paint_jobs, &screen);
    {
        let channel = |c: u8| f64::from(c) / 255.0;
        let mut pass = encoder
            .begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("picture"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color { r: channel(background.r()), g: channel(background.g()), b: channel(background.b()), a: 1.0 }),
                        store: wgpu::StoreOp::Store,
                    },
                    depth_slice: None,
                })],
                depth_stencil_attachment: None,
                occlusion_query_set: None,
                timestamp_writes: None,
                multiview_mask: None,
            })
            .forget_lifetime();
        renderer.render(&mut pass, &paint_jobs, &screen);
    }
    encoder.copy_texture_to_buffer(
        texture.as_image_copy(),
        wgpu::TexelCopyBufferInfo { buffer: &buffer, layout: wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(padded), rows_per_image: None } },
        extent,
    );
    queue.submit(extra.into_iter().chain(std::iter::once(encoder.finish())));

    let (sender, receiver) = std::sync::mpsc::channel();
    buffer.slice(..).map_async(wgpu::MapMode::Read, move |result| {
        let _ = sender.send(result.map_err(|e| e.to_string()));
    });
    device.poll(wgpu::PollType::wait_indefinitely()).map_err(|e| e.to_string())?;
    receiver.recv_timeout(Duration::from_secs(10)).map_err(|e| e.to_string())??;
    let mapped = buffer.slice(..).get_mapped_range().map_err(|e| e.to_string())?;
    let mut pixels = Vec::with_capacity((row * height) as usize);
    for line in mapped.chunks(padded as usize) {
        for pixel in line.get(..row as usize).unwrap_or_default().chunks_exact(4) {
            pixels.extend_from_slice(&[pixel[0], pixel[1], pixel[2], 255]);
        }
    }
    save_rgba(path, &pixels, width, height)
}

/// Save RGBA pixels as a PNG, written like every other file the scanner saves.
pub fn save_rgba(path: &std::path::Path, pixels: &[u8], width: u32, height: u32) -> Result<(), String> {
    let mut png = std::io::Cursor::new(Vec::new());
    image::write_buffer_with_format(&mut png, pixels, width, height, image::ExtendedColorType::Rgba8, image::ImageFormat::Png).map_err(|e| e.to_string())?;
    scanner::saving::save(path, png.get_ref()).map_err(|e| e.to_string())
}
