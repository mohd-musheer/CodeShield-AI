import sys
import subprocess

try:
    from PIL import Image, ImageDraw
except ImportError:
    print("[Favicons] Installing pillow library for image drawing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow"])
    from PIL import Image, ImageDraw

from pathlib import Path

def generate_icons():
    static_dir = Path("static")
    static_dir.mkdir(exist_ok=True)

    # 1. Draw base high-res shield image (512x512)
    img = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield polygon nodes
    # Center is 256, 256. Top is 256, 64. Right is 412, 120. Bottom is 256, 448. Left is 100, 120.
    points = [
        (256, 64),    # top point
        (412, 120),   # top right shoulder
        (412, 320),   # mid right
        (256, 448),   # bottom point
        (100, 320),   # mid left
        (100, 120)    # top left shoulder
    ]
    
    # Draw cyan shield outer border
    draw.polygon(points, fill=(0, 242, 254, 255))
    
    # Draw dark inner body
    inner_points = [
        (256, 96),
        (382, 144),
        (382, 304),
        (256, 408),
        (130, 304),
        (130, 144)
    ]
    draw.polygon(inner_points, fill=(11, 24, 39, 255))

    # Draw checkmark inside shield (representing secure)
    draw.line([(190, 260), (235, 305), (320, 195)], fill=(0, 242, 254, 255), width=24, joint="round")

    # 2. Resize and save target outputs
    img.resize((16, 16), Image.Resampling.LANCZOS).save(static_dir / "favicon-16.png")
    img.resize((32, 32), Image.Resampling.LANCZOS).save(static_dir / "favicon-32.png")
    img.resize((180, 180), Image.Resampling.LANCZOS).save(static_dir / "apple-touch-icon.png")
    img.resize((192, 192), Image.Resampling.LANCZOS).save(static_dir / "android-chrome-192.png")
    img.resize((512, 512), Image.Resampling.LANCZOS).save(static_dir / "android-chrome-512.png")
    
    # Save as .ico containing multiple sizes
    img.save(static_dir / "favicon.ico", format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
    print("[Favicons] Generated icons successfully in static/ directory.")

if __name__ == "__main__":
    generate_icons()
