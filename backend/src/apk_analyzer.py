from datetime import datetime
import os
import json
import re
from loguru import logger
from androguard.core.apk import APK
from utils import Features, Suspicion, Probability, Score, CustomAPK

# Configure logging
logger.remove()
logger.add(lambda msg: print(msg), level="INFO")


# ML MODEL IMPORTS WITH PROPER ERROR HANDLING
# ============================================
ML_MODELS_AVAILABLE = False
try:
    from ml_classes import PackageNameDetector , PermissionPatternDetector , CertificateDetector
    ML_MODELS_AVAILABLE = True
    logger.info("✅ ML detector modules imported successfully")
except ImportError as e:
    ML_IMPORT_ERROR = str(e)
    logger.warning(f"⚠️  ML models not available: {e}")


# MAIN APK ANALYZER CLASS  
# ========================
class APKAnalyzer:
    """
    Comprehensive APK analysis tool with ML-based malware detection.
    This class performs static analysis on Android APK files, extracting
    metadata, permissions, certificates, and applying machine learning
    models for suspicious indicator detection.
    """
    
    def __init__(self, apk_path=None):
        """
        Args:
            apk_path (str, optional): Path to APK file. If None, selects latest from uploads/
            config (dict, optional): Configuration overrides
        """
        logger.info("Initializing APKAnalyzer")
        
        # Set APK path
        if apk_path is None:
            logger.info("No APK path provided, auto-selecting latest from uploads directory")
            apk_path = CustomAPK._get_latest_apk(self)
        
        # Validate APK file exists
        if not os.path.exists(apk_path):
            error_msg = f"APK file not found: {apk_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
        
        self.apk_path = apk_path
        logger.info(f"Using APK file: {apk_path}")
        
        # Initialize permission analyzer
        # self.perm_analyzer = AndroidPermissionAnalyzer()
        
        # Initialize ML models with comprehensive error handling
        self._initialize_ml_models()
        
        logger.info("APKAnalyzer initialization complete")
    
    def _initialize_ml_models(self):
        self.ml_models_loaded = False
        
        if not ML_MODELS_AVAILABLE:
            logger.warning("ML models not available due to import issues")
            logger.warning(f"Import error: {ML_IMPORT_ERROR}")
            return
        
        try:
            logger.info("Initializing ML detection models...")
            
            self.pkg_name_detect = PackageNameDetector()
            logger.debug("✅ PackageNameDetector loaded")
            
            self.perm_risk_detect = PermissionPatternDetector() 
            logger.debug("✅ PermissionPatternDetector loaded")
            
            self.cert_risk_detect = CertificateDetector()
            logger.debug("✅ CertificateDetector loaded")
            
            self.ml_models_loaded = True
            logger.info("✅ All ML models loaded successfully")
            
        except Exception as e:
            error_msg = f"Failed to load ML models: {e}"
            logger.error(error_msg)
            self.ml_models_loaded = False

    # MAIN ANALYSIS METHOD
    # =====================================================
    def analyze(self):
        """
        Perform comprehensive APK analysis.
        Returns:
            dict: Complete analysis results including ML predictions and risk scores
        """
        logger.info(f"Starting comprehensive analysis of {self.apk_path}")

        def extract_cn(subject: str) -> str:
            if not subject:
                return None

            # Normalize separators
            subject = subject.replace("/", ",").replace("=", ":")
            
            # Look for CN or Common Name in any variant
            match = re.search(r"(CN|Common Name)\s*[:=]\s*([^,]+)", subject, re.IGNORECASE)
            return match.group(2).strip() if match else None

        try:
            # Load and parse APK
            logger.info("Loading APK with androguard...")
            apk_obj = APK(self.apk_path)
            logger.info("✅ APK loaded successfully")

            # Extract core APK data
            logger.info("Parsing manifest and extracting metadata...")
            manifest_data = CustomAPK._parse_manifest(self, apk_obj)
            permissions = apk_obj.get_permissions() or []
            certs = apk_obj.get_certificates() or []
            logger.info(f"Found {len(permissions or [])} permissions and {len(certs or [])} certificates")

            # Extract features for ML models
            logger.info("Extracting features for ML analysis...")
            pkg_features = Features._extract_pkg_features(self, apk_obj, manifest_data)

            all_cert_features = Features._extract_cert_features(self, certs[0] if certs else None)
            cert_features = {
                "subject": all_cert_features.get("subject"),
                "issuer": all_cert_features.get("issuer"),
                "subject_common_name": extract_cn(all_cert_features.get("subject")),
                "not_before": all_cert_features.get("not_before"),
                "not_after": all_cert_features.get("not_after"),
                "key_size": all_cert_features.get("key_size"),
            }

            # Run ML predictions
            logger.info("Running ML predictions...")
            sus_pkg = Suspicion._check_pkg_suspicion(self,{k: v for k, v in pkg_features.items() if k != "app_version"})
            sus_perm = Suspicion._check_perm_risk(self,permissions)
            sus_cert = Suspicion._check_cert_risk(self,cert_features)

            # Get probability scores (standardized 0.0-1.0)
            logger.info("Calculating probability scores...")
            pkg_proba = Probability._get_pkg_suspicion_proba(self,pkg_features)
            perm_proba = Probability._get_perm_risk_proba(self,permissions)
            cert_proba = Probability._get_cert_risk_proba(self,cert_features)

            # Calculate file metadata
            logger.info("Calculating file metadata...")
            file_hash = CustomAPK._calculate_hash(self)
            file_name = os.path.basename(self.apk_path) 

            # Extract dangerous permissions (COMMENTED-CHECK VARIABLES IN RISK CALCULATION TOO)
            # logger.info("Identifying dangerous permissions...")
            # dangerous_permissions = self.perm_analyzer.get_dangerous_permissions(permissions)

            # Calculate overall risk scores
            logger.info("Calculating risk scores...")
            ml_confidence = Score._calculate_ml_confidence(self, pkg_proba, perm_proba, cert_proba, dangerous_permissions=[] )
            risk_score = Score._calculate_risk_score(self, sus_pkg, sus_perm, sus_cert, dangerous_permissions=[] )

            # Legacy certificate analysis for backward compatibility
            logger.info("Performing legacy certificate analysis...")

            # Compile final analysis results
            analysis_result = {
                "file_info": {
                    "file_name": file_name,
                    "file_hash": file_hash
                },
                "apk_metadata": pkg_features,
                "certificate_info": all_cert_features,
                "permissions": permissions,
                "flags": {
                    "suspicious_pkg": sus_pkg,
                    "suspicious_permissions": sus_perm,
                    "suspicious_certificate": sus_cert,
                },
                "ml_prediction_result": {
                    "confidence": ml_confidence,
                    "pkg_confidence": pkg_proba,
                    "perm_confidence": perm_proba,
                    "cert_confidence": cert_proba,
                    "risk_score": risk_score,
                },
                "analysis_timestamp": datetime.now().isoformat()
            }



            logger.info(f"✅ Analysis completed successfully. Risk score: {risk_score}/100")
            logger.info(f"ML confidence: {ml_confidence}, Suspicious flags: pkg={sus_pkg}, perm={sus_perm}, cert={sus_cert}")
            
            return analysis_result

        except Exception as e:
            error_msg = f"APK analysis failed: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)


# MAIN EXECUTION
# ========================
if __name__ == "__main__":
    """
    This allows the script to be run directly for quick APK analysis.
    Example usage:
        uv run apk_analyzer.py
        uv run apk_analyzer.py /path/to/specific.apk
    """
    try:
        import sys
        
        # Check if specific APK path provided as command line argument
        apk_path = sys.argv[1] if len(sys.argv) > 1 else None
        
        logger.info("=" * 60)
        logger.info("STARTING APK ANALYSIS")
        logger.info("=" * 60)

        analyzer = APKAnalyzer()

        # Perform analysis
        result = analyzer.analyze()
        
        # Output results
        logger.info("=" * 60)
        logger.info("ANALYSIS COMPLETE")
        logger.info("=" * 60)
        
        print("\n" + json.dumps(result, indent=4, ensure_ascii=False))
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        print(f"Error: {e}")
        sys.exit(1)