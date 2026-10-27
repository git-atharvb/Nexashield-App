import os
import joblib
import pandas as pd
import psutil
import hashlib

class ProcessThreatScanner:
    def __init__(self):
        self.model_dir = os.path.dirname(__file__)
        self.model_path = os.path.join(self.model_dir, "process_threat_model.pkl")
        self.features_path = os.path.join(self.model_dir, "process_threat_features.pkl")
        
        self.model = None
        self.features = None
        self.is_loaded = False
        
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path) and os.path.exists(self.features_path):
            try:
                import warnings
                warnings.filterwarnings("ignore", category=UserWarning)
                
                self.model = joblib.load(self.model_path)
                # CRITICAL: Prevent thread explosion on Windows during sequential inference
                if hasattr(self.model, 'n_jobs'):
                    self.model.n_jobs = 1
                    
                self.features = joblib.load(self.features_path)
                self.is_loaded = True
                print("[+] Process Threat Model loaded successfully.")
            except Exception as e:
                print(f"[-] Failed to load model: {e}")
        else:
            print("[-] Model files not found. Please train the model first.")

    def extract_features(self, proc: psutil.Process = None, pinfo: dict = None):
        """
        Extract real system telemetry features from the live process
        or pre-fetched pinfo dictionary to feed into the Random Forest model.
        """
        cpu_percent = 0.0
        memory_percent = 0.0
        thread_count = 1
        is_system_user = 0
        is_temp_path = 0
        is_appdata_path = 0
        has_network = 0

        if pinfo:
            cpu_percent = pinfo.get('cpu_percent') or 0.0
            memory_percent = pinfo.get('memory_percent') or 0.0
            thread_count = pinfo.get('num_threads') or 1
            username = pinfo.get('username') or ''
            is_system_user = 1 if username.upper() in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'] else 0
            exe = pinfo.get('exe') or ''
            cmdline = " ".join(pinfo.get('cmdline') or [])
            full_path_context = (exe + " " + cmdline).lower()
            is_temp_path = 1 if 'temp' in full_path_context else 0
            is_appdata_path = 1 if 'appdata' in full_path_context else 0
            has_network = pinfo.get('has_network', 0)
        elif proc:
            try:
                cpu_percent = proc.cpu_percent() or 0.0
            except: pass
            
            try:
                memory_percent = proc.memory_percent() or 0.0
            except: pass
            
            try:
                thread_count = proc.num_threads() or 1
            except: pass
            
            try:
                username = proc.username() or ''
                is_system_user = 1 if username.upper() in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'] else 0
            except: pass
            
            try:
                exe = proc.exe() or ''
                cmdline = " ".join(proc.cmdline() or [])
                full_path_context = (exe + " " + cmdline).lower()
                
                is_temp_path = 1 if 'temp' in full_path_context else 0
                is_appdata_path = 1 if 'appdata' in full_path_context else 0
            except: pass
            
            try:
                if hasattr(proc, 'net_connections'):
                    conns = proc.net_connections()
                else:
                    conns = proc.connections()
                has_network = 1 if conns and len(conns) > 0 else 0
            except: pass

        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'thread_count': thread_count,
            'is_system_user': is_system_user,
            'is_temp_path': is_temp_path,
            'is_appdata_path': is_appdata_path,
            'has_network': has_network
        }

    def predict_threat_levels_batch(self, process_list: list) -> list:
        """
        Batch predicts threat levels for a list of process info dicts in a single vectorized pass.
        Annotates each process dict with:
        'ai_level': 1 to 5,
        'ai_color': hex string,
        'ai_prob': float
        Returns the annotated process_list.
        """
        if not self.is_loaded or self.model is None or not process_list:
            for p in process_list:
                p['ai_level'] = 1
                p['ai_color'] = "#00b894"
                p['ai_prob'] = 0.0
            return process_list

        try:
            features_list = [self.extract_features(None, pinfo=p) for p in process_list]
            df = pd.DataFrame(features_list)
            if self.features:
                for col in self.features:
                    if col not in df.columns:
                        df[col] = 0
                df = df[self.features]

            probs = self.model.predict(df)
            
            for p, prob in zip(process_list, probs):
                prob_val = float(prob)
                if prob_val <= 0.20:
                    level, color = 1, "#00b894"  # Green / Safe
                elif prob_val <= 0.40:
                    level, color = 2, "#0984e3"  # Blue / Low Risk
                elif prob_val <= 0.60:
                    level, color = 3, "#fdcb6e"  # Yellow / Moderate Risk
                elif prob_val <= 0.80:
                    level, color = 4, "#e17055"  # Orange / High Risk
                else:
                    level, color = 5, "#d63031"  # Red / Critical
                    
                p['ai_level'] = level
                p['ai_color'] = color
                p['ai_prob'] = prob_val
        except Exception as e:
            print(f"[-] Batch prediction failed: {e}")
            for p in process_list:
                p['ai_level'] = p.get('ai_level') or 1
                p['ai_color'] = p.get('ai_color') or "#00b894"
                p['ai_prob'] = p.get('ai_prob') or 0.0

        return process_list

    def predict_threat_level(self, proc: psutil.Process = None, pinfo: dict = None) -> tuple:
        """
        Predicts threat level (1 to 5) and returns a color for UI mapping.
        Returns: (threat_level, color, probability)
        """
        if not self.is_loaded or self.model is None:
            return (1, "#00b894", 0.0) # Default safe if model not loaded

        try:
            feature_dict = self.extract_features(proc, pinfo=pinfo)
            df = pd.DataFrame([feature_dict])
            if self.features:
                for col in self.features:
                    if col not in df.columns:
                        df[col] = 0
                df = df[self.features]
                
            prob = float(self.model.predict(df)[0])
            
            if prob <= 0.20:
                return (1, "#00b894", prob)  # Green / Safe
            elif prob <= 0.40:
                return (2, "#0984e3", prob)  # Blue / Low Risk
            elif prob <= 0.60:
                return (3, "#fdcb6e", prob)  # Yellow / Moderate Risk
            elif prob <= 0.80:
                return (4, "#e17055", prob)  # Orange / High Risk
            else:
                return (5, "#d63031", prob)  # Red / Critical
                
        except Exception as e:
            return (1, "#636e72", 0.0) # Grey / Unknown
