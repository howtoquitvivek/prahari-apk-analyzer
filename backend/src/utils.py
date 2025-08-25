import hashlib
import os
import re
from loguru import logger
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa


# CONFIGURATION SETTINGS
# =====================================================

UPLOAD_DIR = os.environ.get('APK_UPLOAD_DIR', os.path.join(os.path.dirname(__file__), "../uploads"))
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

ML_CONFIDENCE_THRESHOLDS = {
    'package_suspicion': 0.4,
    'permission_risk': 0.6, 
    'certificate_risk': 0.8
}

RISK_WEIGHTS = {
    'suspicious_package': 35,
    'suspicious_permissions': 30,
    'suspicious_certificate': 15,
    'dangerous_permissions_bonus': 10
}


# PERMISSION ANALYSIS CLASS
class AndroidPermissionAnalyzer:
    def __init__(self):
        logger.info("Initializing AndroidPermissionAnalyzer")
        
        # Android's official dangerous permission patterns
        # Source: https://developer.android.com/reference/android/Manifest.permission
        self.dangerous_permission_patterns = [
            # Location permissions
            r'ACCESS_FINE_LOCATION',
            r'ACCESS_COARSE_LOCATION', 
            r'ACCESS_BACKGROUND_LOCATION',
            
            # Phone and SMS permissions
            r'READ_PHONE_STATE',
            r'READ_PHONE_NUMBERS',
            r'CALL_PHONE',
            r'ANSWER_PHONE_CALLS',
            r'SEND_SMS',
            r'RECEIVE_SMS',
            r'READ_SMS',
            r'RECEIVE_WAP_PUSH',
            r'RECEIVE_MMS',
            
            # Contacts and calendar permissions
            r'READ_CONTACTS',
            r'WRITE_CONTACTS',
            r'GET_ACCOUNTS',
            r'READ_CALENDAR',
            r'WRITE_CALENDAR',
            
            # Media and sensors permissions
            r'CAMERA',
            r'RECORD_AUDIO',
            r'BODY_SENSORS',
            
            # Storage permissions
            r'READ_EXTERNAL_STORAGE',
            r'WRITE_EXTERNAL_STORAGE',
            
            # Call log permissions
            r'READ_CALL_LOG',
            r'WRITE_CALL_LOG',
            r'PROCESS_OUTGOING_CALLS',
            r'ADD_VOICEMAIL',
            r'USE_SIP'
        ]
        
        logger.info(f"Loaded {len(self.dangerous_permission_patterns)} dangerous permission patterns")
    
    def get_dangerous_permissions(self, permissions):
        if not permissions:
            logger.warning("No permissions provided for analysis")
            return []

        logger.info(f"Analyzing {len(permissions)} permissions for dangerous patterns")
        dangerous = []

        for permission in permissions:
            # Extract permission name (remove package prefix if present)
            perm_name = permission.split('.')[-1] if '.' in permission else permission
            
            # Check against dangerous patterns
            for pattern in self.dangerous_permission_patterns:
                if re.search(pattern, perm_name, re.IGNORECASE):
                    dangerous.append(permission)
                    logger.debug(f"Found dangerous permission: {permission}")
                    break

        logger.info(f"Found {len(dangerous)} dangerous permissions out of {len(permissions)} total")
        return dangerous

# FEATURE EXTRACTION METHODS
# =====================================================
class Features:
    def _extract_pkg_features(self, apk_obj, manifest_data):
        logger.debug("Extracting package features for ML analysis")
        try:
            # Calculate file size
            file_size_bytes = os.path.getsize(self.apk_path)
            app_size_mb = round(file_size_bytes / (1024 * 1024), 2)
            
            features = {
                'package_name': manifest_data.get('package', ''),
                'app_name': manifest_data.get('application_label', ''),     #FOCUS
                'app_version': manifest_data.get('version_name', ''),
                'min_sdk': manifest_data.get('min_sdk_version', 0),
                'target_sdk': manifest_data.get('target_sdk_version', 0),
                'app_size_mb': app_size_mb
            }
            
            logger.debug(f"Extracted package features: {features}")
            return features
            
        except Exception as e:
            logger.error(f"Failed to extract package features: {e}")
            return {}

    def _extract_cert_features(self, cert_obj):
        if not cert_obj:
            logger.warning("No certificate object provided")
            return None

        logger.debug(f"Extracting certificate features from {type(cert_obj).__name__}")

        try:
            # Handle different certificate object types
            if isinstance(cert_obj, bytes):
                cert = x509.load_der_x509_certificate(cert_obj, default_backend())
                return Certificate._parse_cryptography_cert(self,cert)
                
            elif type(cert_obj).__name__ == 'Certificate':
                return Certificate._parse_asn1crypto_cert(self,cert_obj)
                
            elif hasattr(cert_obj, 'to_cryptography'):
                cert = cert_obj.to_cryptography()
                return self._parse_cryptography_cert(cert)
                
            else:
                logger.warning(f"Unsupported certificate type: {type(cert_obj).__name__}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to extract certificate features: {e}")
            return None

# CERTIFICATE METHODS
# =====================================================
class Certificate:
    # CERTIFICATE HELPER METHODS
    def _get_key_size(self, public_key):
        """Extract key size in bits."""
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                return public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                return public_key.curve.key_size
            elif isinstance(public_key, dsa.DSAPublicKey):
                return public_key.key_size
            else:
                return 0
        except Exception:
            return 0

    def _estimate_key_size_asn1crypto(self, cert):
        try:
            public_key_info = cert['tbs_certificate']['subject_public_key_info']
            algorithm = public_key_info['algorithm']['algorithm'].dotted
            public_key_bytes = public_key_info['public_key'].contents
            
            # RSA key size estimation
            if 'rsa' in algorithm.lower() or '1.2.840.113549.1.1' in algorithm:
                if len(public_key_bytes) > 400:  # Typical 4096-bit RSA
                    return 4096
                elif len(public_key_bytes) > 200:  # Typical 2048-bit RSA
                    return 2048
                elif len(public_key_bytes) > 150:  # Typical 1024-bit RSA
                    return 1024
                else:
                    return len(public_key_bytes) * 4  # Rough estimation
            
            # ECDSA key size estimation
            elif 'ecdsa' in algorithm.lower() or '1.2.840.10045.2.1' in algorithm:
                if len(public_key_bytes) > 80:
                    return 384  # P-384
                elif len(public_key_bytes) > 60:
                    return 256  # P-256
                else:
                    return 224  # P-224
            
            # DSA key size estimation
            elif 'dsa' in algorithm.lower() or '1.2.840.10040.4.1' in algorithm:
                if len(public_key_bytes) > 300:
                    return 2048
                else:
                    return 1024
            
            return 0
                
        except Exception as e:
            logger.warning(f"Could not estimate key size: {e}")
            return 0

    def _serialize_certificate(self, cert):
        """
        Convert x509 certificate object into JSON-serializable dict.
        Args:
            cert: x509 certificate object   
        Returns:
            dict: Serialized certificate data
        """
        try:
            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat(),
                "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            }
        except Exception as e:
            return {"error": f"Failed to parse certificate: {str(e)}"}

    def _analyze_certificate_legacy(self, apk_obj):
        """
        Legacy certificate analysis for backward compatibility.
        Args:
            apk_obj: Androguard APK object
        Returns:
            dict: Legacy certificate analysis results
        """
        logger.debug("Performing legacy certificate analysis")
        
        certs = apk_obj.get_certificates()
        if not certs:
            logger.warning("No certificates found in APK")
            return {'is_signed': False, 'self_signed': False, 'certificate': {}}

        cert_obj = certs[0]
        logger.debug(f"Analyzing certificate of type: {type(cert_obj).__name__}")

        try:
            # Handle bytes certificate objects
            if isinstance(cert_obj, bytes):
                cert = x509.load_der_x509_certificate(cert_obj, default_backend())
                cert_info = Certificate.erialize_certificate(self,cert)
                is_self_signed = cert.issuer == cert.subject
                logger.debug("Successfully analyzed bytes certificate")
                return {
                    "is_signed": True, 
                    "self_signed": is_self_signed, 
                    "certificate": cert_info
                }

            # Handle Androguard Certificate objects (asn1crypto)
            elif type(cert_obj).__name__ == 'Certificate':
                subject = cert_obj.subject.human_friendly
                issuer = cert_obj.issuer.human_friendly
                not_before = cert_obj['tbs_certificate']['validity']['not_before'].native.isoformat()
                not_after = cert_obj['tbs_certificate']['validity']['not_after'].native.isoformat()
                fingerprint_sha256 = cert_obj.sha256.hex()

                cert_info = {
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "fingerprint_sha256": fingerprint_sha256,
                }
                is_self_signed = (cert_obj.subject == cert_obj.issuer)
                logger.debug("Successfully analyzed asn1crypto certificate")
                return {
                    "is_signed": True, 
                    "self_signed": is_self_signed, 
                    "certificate": cert_info
                }

            # Handle pyOpenSSL or cryptography objects
            elif hasattr(cert_obj, 'to_cryptography'):
                cert = cert_obj.to_cryptography()
                cert_info = Certificate._serialize_certificate(self, cert)
                is_self_signed = cert.issuer == cert.subject
                logger.debug("Successfully analyzed convertible certificate")
                return {
                    'is_signed': True,
                    'self_signed': is_self_signed,
                    'certificate': cert_info
                }

            else:
                logger.warning(f"Unsupported certificate type: {type(cert_obj).__name__}")
                return {
                    'is_signed': True,
                    'self_signed': False,
                    'certificate': {
                        "note": f"Unsupported certificate type: {type(cert_obj).__name__}"
                    }
                }

        except Exception as e:
            logger.error(f"Failed to analyze certificate: {e}")
            return {
                'is_signed': True,
                'self_signed': False,
                'certificate': {"error": f"Failed to parse certificate: {str(e)}"}
            }


    # CERTIFICATE PARSING METHODS
    def _parse_cryptography_cert(self, cert):
        try:
            logger.debug("Parsing cryptography certificate")
            
            # Extract basic certificate information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            not_before = cert.not_valid_before.isoformat()
            not_after = cert.not_valid_after.isoformat()
            
            # Generate fingerprints
            sha1_fingerprint = cert.fingerprint(hashes.SHA1()).hex()
            sha256_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            md5_fingerprint = cert.fingerprint(hashes.MD5()).hex()
            
            # Extract public key information
            public_key = cert.public_key()
            key_size =  Certificate._get_key_size(self,public_key)

            version = cert.version.value
            
            features = {
                'subject': subject,
                'issuer': issuer,
                'not_before': not_before,
                'not_after': not_after,
                'sha1_fingerprint': sha1_fingerprint,
                'sha256_fingerprint': sha256_fingerprint,
                'md5_fingerprint': md5_fingerprint,
                'key_size': key_size,
                'version': version,
            }
            
            logger.debug("Successfully parsed cryptography certificate")
            return features
            
        except Exception as e:
            logger.error(f"Error parsing cryptography certificate: {e}")
            return None

    def _parse_asn1crypto_cert(self, cert):
        try:
            logger.debug("Parsing asn1crypto certificate")
            
            # Extract basic information
            subject = cert.subject.human_friendly
            issuer = cert.issuer.human_friendly
            not_before = cert['tbs_certificate']['validity']['not_before'].native.isoformat()
            not_after = cert['tbs_certificate']['validity']['not_after'].native.isoformat()
            
            # Generate fingerprints
            sha1_fingerprint = cert.sha1.hex()
            sha256_fingerprint = cert.sha256.hex()
            
            # Calculate MD5 fingerprint manually if not available
            try:
                md5_fingerprint = cert.md5.hex()
            except AttributeError:
                md5_hash = hashlib.md5(cert.dump()).hexdigest()
                md5_fingerprint = md5_hash
            
            
            # Estimate key size
            key_size = Certificate._estimate_key_size_asn1crypto(self,cert)
            
            try:
                version = cert['tbs_certificate']['version'].native + 1  # X.509 versions are 0-indexed
            except Exception:
                version = 3  # Default to v3
            
            features = {
                'subject': subject,
                'issuer': issuer,
                'not_before': not_before,
                'not_after': not_after,
                'sha1_fingerprint': sha1_fingerprint,
                'sha256_fingerprint': sha256_fingerprint,
                'md5_fingerprint': md5_fingerprint,
                'key_size': key_size,
                'version': version,
            }
            
            logger.debug("Successfully parsed asn1crypto certificate")
            return features
            
        except Exception as e:
            logger.error(f"Error parsing asn1crypto certificate: {e}")
            return None

# ML SUSPICION PREDICTION METHODS
# =====================================================
class Suspicion:
    def _check_pkg_suspicion(self, pkg_features):
        if not self.ml_models_loaded:
            logger.debug("ML models not loaded, using rule-based detection")
            return False

        try:
            logger.debug("Running ML package suspicion detection")
            result = self.pkg_name_detect.predict(
                pkg_features.get('package_name', ''),
                pkg_features.get('app_name', ''),
                int(pkg_features.get('min_sdk', 0) or 0),
                int(pkg_features.get('target_sdk', 0) or 0),
                float(pkg_features.get('app_size_mb', 0.0) or 0.0)
            )
            logger.debug(f"ML package suspicion result: {result}")
            return result
        
        except Exception as e:
            logger.error(f"Package ML prediction failed: {e}")
            return False

    def _check_perm_risk(self, permissions: list[str]) -> bool:
        try:
            return self.perm_risk_detect.predict(permissions)
        except Exception as e:
            logger.error(f"Permission ML prediction failed: {e}")
            return False

    def _check_cert_risk(self, cert_features):
        if not self.ml_models_loaded or not cert_features:
            logger.debug("ML models not loaded or no certificate features")
            return False
            
        try:
            logger.debug("Running ML certificate risk detection")
            result = self.cert_risk_detect.predict(cert_features)
            logger.debug(f"ML certificate risk result: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Certificate ML prediction failed: {e}")
            return False

# SUSPICION PROBABILITY SCORING METHODS
# =====================================================
class Probability:
    def _get_pkg_suspicion_proba(self, pkg_features):
        try:
            proba = self.pkg_name_detect.predict_proba(
                pkg_features.get('package_name', ''),
                pkg_features.get('app_name', ''),
                int(pkg_features.get('min_sdk', 0) or 0),
                int(pkg_features.get('target_sdk', 0) or 0),
                float(pkg_features.get('app_size_mb', 0.0) or 0.0)
            )
            return float(proba)  # Ensure it's a float between 0-1
            
        except Exception as e:
            logger.error(f"Package ML probability failed: {e}")

    def _get_perm_risk_proba(self, permissions: list[str]) -> float:
        try:
            return self.perm_risk_detect.predict_proba(permissions)
        except Exception as e:
            logger.error(f"Permission ML probability failed: {e}")
            return 0.0

    def _get_cert_risk_proba(self, cert_features):
        try:
            proba = self.cert_risk_detect.predict_proba(cert_features)
            return float(proba)  # Ensure it's a float between 0-1
            
        except Exception as e:
            logger.error(f"Certificate ML probability failed: {e}")


# RISK and CONFIDENCE SCORING METHODS
# =====================================================
class Score:
    def _calculate_ml_confidence(self, pkg_proba, perm_proba, cert_proba, dangerous_permissions):
        """
        Calculate overall ML confidence using weighted average of probabilities.
        Args:
            pkg_proba (float): Package suspicion probability (0.0-1.0)
            perm_proba (float): Permission risk probability (0.0-1.0)
            cert_proba (float): Certificate risk probability (0.0-1.0)
            dangerous_permissions (list): List of dangerous permissions
        Returns:
            float: Overall confidence score (0.0-1.0)
        """
        logger.debug("Calculating ML confidence score")
        
        # Weighted average of ML model probabilities
        weights = {
            'package': 0.35,     # Package name analysis weight
            'permissions': 0.35, # Permission pattern analysis weight  
            'certificate': 0.30  # Certificate analysis weight
        }
        
        # Calculate weighted confidence
        confidence = (
            weights['package'] * pkg_proba + 
            weights['permissions'] * perm_proba + 
            weights['certificate'] * cert_proba
        )
        
        # Optional: boost confidence based on dangerous permissions count
        dangerous_count = len(dangerous_permissions)
        if dangerous_count > 10:
            confidence = min(1.0, confidence + 0.10)  # Large boost for many dangerous perms
            logger.debug(f"Applied large dangerous permissions boost (+0.10)")
        elif dangerous_count > 5:
            confidence = min(1.0, confidence + 0.05)  # Small boost for moderate dangerous perms
            logger.debug(f"Applied small dangerous permissions boost (+0.05)")
        
        final_confidence = round(confidence, 3)  # Round to 3 decimal places
        logger.debug(f"Final ML confidence: {final_confidence}")
        return final_confidence

    def _calculate_risk_score(self, sus_pkg, sus_perm, sus_cert, dangerous_permissions):
        """
        Calculate risk score from 0-100 based on analysis results.
        Args:
            sus_pkg (bool): Package suspicion flag
            sus_perm (bool): Permission risk flag
            sus_cert (bool): Certificate risk flag
            dangerous_permissions (list): List of dangerous permissions
        Returns:
            int: Risk score (0-100)
        """
        logger.debug("Calculating overall risk score")
        
        score = 0
        
        # Add base scores for suspicions using configured weights
        if sus_pkg:
            score += RISK_WEIGHTS['suspicious_package']
            logger.debug(f"Added suspicious package score: +{RISK_WEIGHTS['suspicious_package']}")
            
        if sus_perm:
            score += RISK_WEIGHTS['suspicious_permissions'] 
            logger.debug(f"Added suspicious permissions score: +{RISK_WEIGHTS['suspicious_permissions']}")
            
        if sus_cert:
            score += RISK_WEIGHTS['suspicious_certificate']
            logger.debug(f"Added suspicious certificate score: +{RISK_WEIGHTS['suspicious_certificate']}")
        
        # Additional score for dangerous permissions
        dangerous_count = len(dangerous_permissions)
        if dangerous_count > 3:
            bonus_points = min(RISK_WEIGHTS['dangerous_permissions_bonus'], dangerous_count)
            score += bonus_points
            logger.debug(f"Added dangerous permissions bonus: +{bonus_points}")
        
        # Cap final score at 100
        final_score = min(100, score)
        logger.debug(f"Final risk score: {final_score}/100")
        return final_score


# HELPERS

class CustomAPK : 
    def _parse_manifest(self, apk_obj):
        """
        Parse AndroidManifest.xml using androguard with comprehensive error handling.
        Args:
            apk_obj: Androguard APK object   
        Returns:
            dict: Parsed manifest data
        """
        logger.debug("Parsing AndroidManifest.xml")
        
        try:
            # Extract SDK versions with fallback handling
            try:
                min_sdk = apk_obj.get_min_sdk_version()
                target_sdk = apk_obj.get_target_sdk_version()
            except Exception as e:
                logger.warning(f"Could not extract SDK versions: {e}")
                min_sdk = 0
                target_sdk = 0

            # Extract version information with fallback handling
            try:
                version_name = apk_obj.get_androidversion_name() or "Unknown"
                version_code = apk_obj.get_androidversion_code() or "Unknown"
                app_name = apk_obj.get_app_name() or "Unknown"      #FOCUS
                package = apk_obj.package or "Unknown"
            except Exception as e:
                logger.warning(f"Could not extract version info: {e}")
                version_name = "Unknown"
                version_code = "Unknown"
                app_name = "Unknown"
                package = "Unknown"

            manifest_data = {
                'package': package,
                'version_name': version_name,
                'version_code': version_code,
                'application_label': app_name,
                'min_sdk_version': min_sdk,
                'target_sdk_version': target_sdk
            }
            
            logger.debug(f"Successfully parsed manifest: {manifest_data}")
            return manifest_data
            
        except Exception as e:
            logger.error(f"Failed to parse manifest: {e}")
            # Return minimal fallback data
            return {
                'package': 'Unknown',
                'version_name': 'Unknown', 
                'version_code': 'Unknown',
                'application_label': 'Unknown',
                'min_sdk_version': 0,
                'target_sdk_version': 0
            }

    def _calculate_hash(self):
        """
        Calculate SHA-256 hash of APK file.
        Returns:
            str: SHA-256 hash in hexadecimal format
        """
        logger.debug(f"Calculating SHA-256 hash for {self.apk_path}")
        
        try:
            sha256_hash = hashlib.sha256()
            with open(self.apk_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            hash_value = sha256_hash.hexdigest()
            logger.debug(f"Calculated hash: {hash_value}")
            return hash_value
            
        except Exception as e:
            logger.error(f"Failed to calculate file hash: {e}")
            return "hash_calculation_failed"

    def _get_latest_apk(self):
        """
        Get latest uploaded APK from configured uploads directory.
        Returns:
            str: Path to latest APK file
        Raises:
            FileNotFoundError: If no APK files found or upload directory doesn't exist
        """
        logger.info(f"Searching for latest APK in: {UPLOAD_DIR}")
        
        if not os.path.exists(UPLOAD_DIR):
            error_msg = f"Uploads directory not found: {UPLOAD_DIR}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
            
        # Find all APK files
        apk_files = [f for f in os.listdir(UPLOAD_DIR) if f.lower().endswith(".apk")]
        
        if not apk_files:
            error_msg = f"No APK files found in uploads directory: {UPLOAD_DIR}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
        
        # Get the most recently modified APK
        latest_apk = max(apk_files, key=lambda f: os.path.getmtime(os.path.join(UPLOAD_DIR, f)))
        full_path = os.path.join(UPLOAD_DIR, latest_apk)
        
        logger.info(f"Selected latest APK: {latest_apk}")
        return full_path
