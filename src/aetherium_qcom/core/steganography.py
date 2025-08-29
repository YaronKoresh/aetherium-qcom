# aetherium_qcom/core/steganography.py
import os
import wave
import tempfile
from datetime import datetime
from PIL import Image
import numpy as np
from pydub import AudioSegment
from moviepy import VideoFileClip, AudioFileClip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib

class SteganographyManager:
    # Recommended constant salt (public, not secret):
    _PBKDF2_SALT = b"StegSalt"
    def _get_magic_number(self, password):
        # Use PBKDF2HMAC for password-derived magic number
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=5,
            salt=self._PBKDF2_SALT,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.generate(password.encode())

    def embed(self, input_path, data_bytes, password):
        _, ext = os.path.splitext(input_path.lower())
        img_ext = ['.png', '.jpg', '.jpeg', '.bmp', '.webp']
        aud_ext = ['.wav', '.mp3', '.m4a', '.flac', '.ogg']
        vid_ext = ['.mp4', '.mov', '.avi', '.mkv']

        magic_number = self._get_magic_number(password)
        data_with_header = magic_number + data_bytes

        if ext in img_ext:
            return self._embed_in_image(input_path, data_with_header, password)
        elif ext in aud_ext:
            return self._embed_in_audio(input_path, data_with_header, password)
        elif ext in vid_ext:
            return self._embed_in_video(input_path, data_with_header, password)
        else:
            return None, f"Unsupported file type: {ext}"

    def extract(self, input_path, password):
        _, ext = os.path.splitext(input_path.lower())
        img_ext = ['.png', '.jpg', '.jpeg', '.bmp', '.webp']
        aud_ext = ['.wav', '.mp3', '.m4a', '.flac', '.ogg']
        vid_ext = ['.mp4', '.mov', '.avi', '.mkv']

        data_with_header, error = None, None
        magic_number = self._get_magic_number(password)

        if ext in img_ext:
            data_with_header, error = self._extract_from_image(input_path, password)
        elif ext in aud_ext:
            data_with_header, error = self._extract_from_audio(input_path, password)
        elif ext in vid_ext:
            data_with_header, error = self._extract_from_video(input_path, password)
        else:
            return None, f"Unsupported file type: {ext}"

        if error:
            return None, error
        
        if data_with_header and data_with_header.startswith(magic_number):
            return data_with_header[len(magic_number):], None
        else:
            return None, "No invitation data found in media file or incorrect password."

    def _embed_in_image(self, image_path, data, password):
        try:
            with Image.open(image_path) as img:
                img = img.convert("RGB")
                w, h = img.size
                bits = ''.join(format(byte, '08b') for byte in data)
                data_len_bits = format(len(bits), '032b')
                total_bits = data_len_bits + bits
                
                if len(total_bits) > w * h * 3: return None, "Data too large for image."
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self._PBKDF2_SALT,
                    iterations=100_000,
                    backend=default_backend()
                )
                seed_bytes = kdf.derive(password.encode())
                rng = np.random.default_rng(int.from_bytes(seed_bytes, 'big'))
                indices = rng.choice(w * h * 3, len(total_bits), replace=False)
                
                flat_pixel_data = [chan for pix in img.getdata() for chan in pix]

                for i, bit in enumerate(total_bits):
                    idx = indices[i]
                    flat_pixel_data[idx] = (flat_pixel_data[idx] & 0xFE) | int(bit)

                img.putdata(list(zip(*[iter(flat_pixel_data)]*3)))
                
                output_path = f"invitation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                img.save(output_path, 'PNG')
                return output_path, None
        except Exception as e: return None, f"Image embedding error: {e}"

    def _extract_from_image(self, image_path, password):
        try:
            with Image.open(image_path) as img:
                img = img.convert("RGB")
                w, h = img.size
                seed_bytes = hashlib.pbkdf2_hmac(
                    "sha256",
                    password.encode(),
                    self._PBKDF2_SALT,
                    100_000,
                    dklen=32
                )
                rng = np.random.default_rng(int.from_bytes(seed_bytes, 'big'))
                
                flat_pixel_data = [chan for pix in img.getdata() for chan in pix]

                len_indices = rng.choice(w * h * 3, 32, replace=False)
                len_bits = "".join(str(flat_pixel_data[i] & 1) for i in len_indices)
                data_len = int(len_bits, 2)

                if data_len > w * h * 3: return None, "Corrupt data length."
                
                all_indices = rng.choice(w * h * 3, 32 + data_len, replace=False)
                data_indices = all_indices[32:]
                
                bits = "".join(str(flat_pixel_data[i] & 1) for i in data_indices)
                return bytearray(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)), None
        except Exception as e: return None, f"Image extraction error: {e}"

    def _lsb_embed_in_wav(self, wav_path, data_to_embed):
        with wave.open(wav_path, 'rb') as wav_file:
            frames = bytearray(wav_file.readframes(wav_file.getnframes()))
        
        bits_to_embed = ''.join(format(byte, '08b') for byte in data_to_embed)
        data_len_bits = format(len(bits_to_embed), '032b')
        total_bits = data_len_bits + bits_to_embed

        if len(total_bits) > len(frames):
            raise ValueError("Data is too large for the audio file.")

        for i, bit in enumerate(total_bits):
            frames[i] = (frames[i] & 0xFE) | int(bit)

        return bytes(frames)

    def _lsb_extract_from_wav(self, wav_path):
        with wave.open(wav_path, 'rb') as wav_file:
            frames = wav_file.readframes(wav_file.getnframes())

        len_bits = "".join([str(frames[i] & 1) for i in range(32)])
        data_len = int(len_bits, 2)
        
        if data_len > (len(frames) - 32):
             raise ValueError("Corrupt data length found in audio.")

        data_bits = "".join([str(frames[i] & 1) for i in range(32, 32 + data_len)])
        return bytearray(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))

    def _embed_in_audio(self, audio_path, data, password):
        try:
            audio = AudioSegment.from_file(audio_path)
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_wav:
                audio.export(temp_wav.name, format="wav")
            
            modified_frames = self._lsb_embed_in_wav(temp_wav.name, data)

            with wave.open(temp_wav.name, 'rb') as wav_file:
                params = wav_file.getparams()

            output_path = f"invitation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
            with wave.open(output_path, 'wb') as new_wav:
                new_wav.setparams(params)
                new_wav.writeframes(modified_frames)
            
            os.remove(temp_wav.name)
            return output_path, None
        except Exception as e:
            if 'temp_wav' in locals() and os.path.exists(temp_wav.name): os.remove(temp_wav.name)
            return None, f"Audio embedding error: {e}"

    def _extract_from_audio(self, audio_path, password):
        try:
            audio = AudioSegment.from_file(audio_path)
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_wav:
                audio.export(temp_wav.name, format="wav")
            
            extracted_data = self._lsb_extract_from_wav(temp_wav.name)
            os.remove(temp_wav.name)
            return extracted_data, None
        except Exception as e:
            if 'temp_wav' in locals() and os.path.exists(temp_wav.name): os.remove(temp_wav.name)
            return None, f"Audio extraction error: {e}"

    def _embed_in_video(self, video_path, data, password):
        try:
            video_clip = VideoFileClip(video_path)
            if not video_clip.audio:
                return None, "Video has no audio track to embed data in."

            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_audio:
                video_clip.audio.write_audiofile(temp_audio.name, verbose=False, logger=None)
            
            modified_frames = self._lsb_embed_in_wav(temp_audio.name, data)

            with wave.open(temp_audio.name, 'rb') as wav_file:
                params = wav_file.getparams()
            
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as modified_audio_file:
                 with wave.open(modified_audio_file.name, 'wb') as new_wav:
                    new_wav.setparams(params)
                    new_wav.writeframes(modified_frames)

            new_audio_clip = AudioFileClip(modified_audio_file.name)
            final_clip = video_clip.set_audio(new_audio_clip)
            
            output_path = f"invitation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mp4"
            final_clip.write_videofile(output_path, codec='libx264', audio_codec='aac', verbose=False, logger=None)
            
            os.remove(temp_audio.name)
            os.remove(modified_audio_file.name)
            return output_path, None
        except Exception as e:
            if 'temp_audio' in locals() and os.path.exists(temp_audio.name): os.remove(temp_audio.name)
            if 'modified_audio_file' in locals() and os.path.exists(modified_audio_file.name): os.remove(modified_audio_file.name)
            return None, f"Video embedding error: {e}"

    def _extract_from_video(self, video_path, password):
        try:
            video_clip = VideoFileClip(video_path)
            if not video_clip.audio:
                return None, "Video has no audio track."

            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_audio:
                video_clip.audio.write_audiofile(temp_audio.name, verbose=False, logger=None)

            extracted_data = self._lsb_extract_from_wav(temp_audio.name)
            os.remove(temp_audio.name)
            return extracted_data, None
        except Exception as e:
            if 'temp_audio' in locals() and os.path.exists(temp_audio.name): os.remove(temp_audio.name)
            return None, f"Video extraction error: {e}"