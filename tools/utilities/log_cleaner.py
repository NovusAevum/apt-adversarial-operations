("~/.bash_history"),
                os.path.expanduser("~/.zsh_history"),
                os.path.expanduser("~/.python_history")
            ]
            
            for hist in history_files:
                if os.path.exists(hist):
                    os.remove(hist)
                    print(f"[+] Removed {hist}")
    
    def clear_temp_files(self):
        """Remove temporary files"""
        if self.os_type == "Windows":
            temp_dirs = [
                os.getenv('TEMP'),
                os.getenv('TMP'),
                "C:\\Windows\\Temp"
            ]
        else:
            temp_dirs = ["/tmp", "/var/tmp"]
        
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for file in os.listdir(temp_dir):
                    try:
                        os.remove(os.path.join(temp_dir, file))
                    except:
                        pass
    
    def clean_all(self):
        """Execute all cleaning operations"""
        print("[*] Starting log cleaning...")
        
        if self.os_type == "Windows":
            self.clear_windows_logs()
        else:
            self.clear_linux_logs()
        
        self.remove_command_history()
        self.clear_temp_files()
        
        print("[*] Cleaning complete!")

if __name__ == "__main__":
    cleaner = LogCleaner()
    cleaner.clean_all()
