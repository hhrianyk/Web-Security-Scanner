from PIL import Image, ImageDraw, ImageFont
import os

def create_security_logo():
    # Create a new image with a white background
    img = Image.new('RGB', (300, 300), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    
    # Draw a shield outline
    shield_points = [
        (150, 30),  # Top
        (270, 90),  # Right top
        (240, 240),  # Right bottom
        (150, 270),  # Bottom
        (60, 240),   # Left bottom
        (30, 90)     # Left top
    ]
    draw.polygon(shield_points, outline=(0, 0, 180), fill=(230, 240, 255))
    
    # Draw a lock symbol
    # Lock body
    draw.rectangle((110, 120, 190, 210), outline=(0, 0, 150), fill=(0, 80, 200), width=3)
    # Lock shackle
    draw.arc((115, 80, 185, 130), start=0, end=180, fill=(0, 0, 150), width=5)
    # Lock keyhole
    draw.ellipse((140, 150, 160, 170), outline=(255, 255, 255), fill=(200, 220, 255))
    draw.rectangle((145, 160, 155, 180), outline=(255, 255, 255), fill=(200, 220, 255))
    
    # Add text
    try:
        # Try to find a font that exists (system dependent)
        font = ImageFont.truetype("arial.ttf", 20)
        draw.text((85, 230), "SECURITY SCAN", fill=(0, 0, 150), font=font)
    except IOError:
        # Fallback to default font
        font = ImageFont.load_default()
        draw.text((100, 230), "SECURITY SCAN", fill=(0, 0, 150))
    
    # Save the image
    os.makedirs('static/img', exist_ok=True)
    img.save('static/img/security_logo.png')
    print("Logo created successfully at static/img/security_logo.png")

if __name__ == "__main__":
    create_security_logo() 