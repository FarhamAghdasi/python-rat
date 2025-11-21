import base64
import os

def encode_file_to_base64(file_path, output_file):
    """تبدیل فایل به base64 و ذخیره در فایل"""
    try:
        with open(file_path, 'rb') as f:
            binary_data = f.read()
        
        b64_encoded = base64.b64encode(binary_data).decode('utf-8')
        
        # تقسیم به خطوط کوچکتر برای خوانایی
        chunk_size = 76  # استاندارد MIME
        chunks = [b64_encoded[i:i+chunk_size] for i in range(0, len(b64_encoded), chunk_size)]
        formatted_b64 = '\n'.join(chunks)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(formatted_b64)
        
        print(f"✅ فایل با موفقیت encode شد: {output_file}")
        print(f"📊 حجم اصلی: {len(binary_data)} بایت")
        print(f"📊 حجم base64: {len(b64_encoded)} کاراکتر")
        
        return b64_encoded
        
    except Exception as e:
        print(f"❌ خطا در encode: {str(e)}")
        return None

def decode_base64_to_file(b64_string, output_file):
    """تبدیل base64 به فایل"""
    try:
        # حذف خطوط و فضاهای خالی
        clean_b64 = ''.join(b64_string.split())
        
        binary_data = base64.b64decode(clean_b64)
        
        with open(output_file, 'wb') as f:
            f.write(binary_data)
        
        print(f"✅ فایل با موفقیت decode شد: {output_file}")
        return True
        
    except Exception as e:
        print(f"❌ خطا در decode: {str(e)}")
        return False

if __name__ == "__main__":
    # مسیر فایل mimikatz.exe
    mimikatz_path = "mimikatz.exe"
    output_b64_file = "mimikatz_b64.txt"
    
    if os.path.exists(mimikatz_path):
        encode_file_to_base64(mimikatz_path, output_b64_file)
    else:
        print(f"❌ فایل {mimikatz_path} پیدا نشد")
        print("📝 لطفاً فایل mimikatz.exe را در همین پوشه قرار دهید")