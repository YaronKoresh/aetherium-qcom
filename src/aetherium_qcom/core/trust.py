# aetherium_qcom/core/trust.py
"""
Web of Trust (WoT) system for decentralized reputation management.

This module provides functionality for:
- Vouching for contacts (cryptographic endorsement)
- Filing accusations with cryptographic proofs
- Calculating trust scores based on the web of trust
"""

import json
import time
from typing import Dict, List, Tuple
from .crypto import CryptoManager


class TrustProof:
    """Represents cryptographic proof for an accusation."""
    
    PROOF_TYPE_SPAM = "spam"
    PROOF_TYPE_CRYPTO_FAILURE = "crypto_failure"
    PROOF_TYPE_MALICIOUS_CONTENT = "malicious_content"
    PROOF_TYPE_IMPERSONATION = "impersonation"
    
    @staticmethod
    def create_spam_proof(accuser_id: str, accused_id: str, message_signatures: List[str], 
                          accuser_signing_key: str, description: str = "") -> Dict:
        """
        Create a spam accusation proof.
        
        Args:
            accuser_id: ID of the user making the accusation
            accused_id: ID of the accused user
            message_signatures: List of message signatures as evidence
            accuser_signing_key: Accuser's signing key (to sign the proof)
            description: Optional description of the spam behavior
            
        Returns:
            Dictionary containing the proof
        """
        proof_data = {
            "type": TrustProof.PROOF_TYPE_SPAM,
            "accuser_id": accuser_id,
            "accused_id": accused_id,
            "timestamp": int(time.time()),
            "evidence": {
                "message_signatures": message_signatures,
                "description": description
            }
        }
        
        # Sign the proof
        signature = CryptoManager.sign_data(accuser_signing_key, proof_data)
        
        return {
            "proof": proof_data,
            "signature": signature
        }
    
    @staticmethod
    def create_crypto_failure_proof(accuser_id: str, accused_id: str, 
                                    failed_challenge: str, accuser_signing_key: str,
                                    description: str = "") -> Dict:
        """
        Create a cryptographic failure accusation proof.
        
        Args:
            accuser_id: ID of the user making the accusation
            accused_id: ID of the accused user
            failed_challenge: Evidence of failed cryptographic verification
            accuser_signing_key: Accuser's signing key
            description: Optional description
            
        Returns:
            Dictionary containing the proof
        """
        proof_data = {
            "type": TrustProof.PROOF_TYPE_CRYPTO_FAILURE,
            "accuser_id": accuser_id,
            "accused_id": accused_id,
            "timestamp": int(time.time()),
            "evidence": {
                "failed_challenge": failed_challenge,
                "description": description
            }
        }
        
        signature = CryptoManager.sign_data(accuser_signing_key, proof_data)
        
        return {
            "proof": proof_data,
            "signature": signature
        }
    
    @staticmethod
    def create_malicious_content_proof(accuser_id: str, accused_id: str,
                                      content_evidence: str, accuser_signing_key: str,
                                      description: str = "") -> Dict:
        """
        Create a malicious content accusation proof.
        
        Args:
            accuser_id: ID of the user making the accusation
            accused_id: ID of the accused user
            content_evidence: Evidence of malicious content (e.g., hashes, screenshots)
            accuser_signing_key: Accuser's signing key
            description: Optional description
            
        Returns:
            Dictionary containing the proof
        """
        proof_data = {
            "type": TrustProof.PROOF_TYPE_MALICIOUS_CONTENT,
            "accuser_id": accuser_id,
            "accused_id": accused_id,
            "timestamp": int(time.time()),
            "evidence": {
                "content_evidence": content_evidence,
                "description": description
            }
        }
        
        signature = CryptoManager.sign_data(accuser_signing_key, proof_data)
        
        return {
            "proof": proof_data,
            "signature": signature
        }
    
    @staticmethod
    def create_impersonation_proof(accuser_id: str, accused_id: str,
                                   impersonation_evidence: str, accuser_signing_key: str,
                                   description: str = "") -> Dict:
        """
        Create an impersonation accusation proof.
        
        Args:
            accuser_id: ID of the user making the accusation
            accused_id: ID of the accused user
            impersonation_evidence: Evidence of impersonation (e.g., fake profile data)
            accuser_signing_key: Accuser's signing key
            description: Optional description
            
        Returns:
            Dictionary containing the proof
        """
        proof_data = {
            "type": TrustProof.PROOF_TYPE_IMPERSONATION,
            "accuser_id": accuser_id,
            "accused_id": accused_id,
            "timestamp": int(time.time()),
            "evidence": {
                "impersonation_evidence": impersonation_evidence,
                "description": description
            }
        }
        
        signature = CryptoManager.sign_data(accuser_signing_key, proof_data)
        
        return {
            "proof": proof_data,
            "signature": signature
        }
    
    @staticmethod
    def verify_proof(proof_with_signature: Dict, accuser_public_key: str) -> bool:
        """
        Verify a trust proof's cryptographic signature.
        
        Args:
            proof_with_signature: Proof dictionary with signature
            accuser_public_key: Public key of the accuser
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            proof_data = proof_with_signature["proof"]
            signature = proof_with_signature["signature"]
            return CryptoManager.verify_signature(accuser_public_key, signature, proof_data)
        except (KeyError, Exception):
            return False


class VouchManager:
    """Manages vouches (endorsements) between users."""
    
    @staticmethod
    def create_vouch(voucher_id: str, vouched_id: str, vouched_public_key: str,
                     voucher_signing_key: str, trust_level: int = 1) -> Dict:
        """
        Create a vouch (endorsement) for another user.
        
        Args:
            voucher_id: ID of the user making the vouch
            vouched_id: ID of the user being vouched for
            vouched_public_key: Public signing key of vouched user (to verify identity)
            voucher_signing_key: Voucher's signing key
            trust_level: Level of trust (1-5, where 5 is highest)
            
        Returns:
            Dictionary containing the vouch
        """
        if trust_level < 1 or trust_level > 5:
            raise ValueError("Trust level must be between 1 and 5")
        
        vouch_data = {
            "voucher_id": voucher_id,
            "vouched_id": vouched_id,
            "vouched_public_key": vouched_public_key,
            "trust_level": trust_level,
            "timestamp": int(time.time())
        }
        
        # Sign the vouch
        signature = CryptoManager.sign_data(voucher_signing_key, vouch_data)
        
        return {
            "vouch": vouch_data,
            "signature": signature
        }
    
    @staticmethod
    def verify_vouch(vouch_with_signature: Dict, voucher_public_key: str) -> bool:
        """
        Verify a vouch's cryptographic signature.
        
        Args:
            vouch_with_signature: Vouch dictionary with signature
            voucher_public_key: Public key of the voucher
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            vouch_data = vouch_with_signature["vouch"]
            signature = vouch_with_signature["signature"]
            return CryptoManager.verify_signature(voucher_public_key, signature, vouch_data)
        except (KeyError, Exception):
            return False


class TrustCalculator:
    """Calculates trust scores based on vouches and accusations."""
    
    # Trust score weights
    VOUCH_WEIGHT = 10  # Points added per vouch
    ACCUSATION_WEIGHT = -50  # Points deducted per accusation
    TRUSTED_VOUCH_MULTIPLIER = 2.0  # Multiplier for vouches from trusted contacts
    TRUSTED_ACCUSATION_MULTIPLIER = 2.0  # Multiplier for accusations from trusted contacts
    
    @staticmethod
    def calculate_trust_score(vouches: List[Dict], accusations: List[Dict],
                             my_trusted_contacts: List[str] = None) -> Tuple[int, Dict]:
        """
        Calculate a trust score for a user based on vouches and accusations.
        
        Args:
            vouches: List of vouch dictionaries
            accusations: List of accusation dictionaries
            my_trusted_contacts: List of user IDs that I personally trust
            
        Returns:
            Tuple of (trust_score, trust_details) where:
            - trust_score: Integer score (can be negative)
            - trust_details: Dictionary with breakdown of score calculation
        """
        if my_trusted_contacts is None:
            my_trusted_contacts = []
        
        score = 0
        details = {
            "total_vouches": len(vouches),
            "total_accusations": len(accusations),
            "vouches_from_trusted": 0,
            "accusations_from_trusted": 0,
            "trust_level_sum": 0
        }
        
        # Calculate vouch contribution
        for vouch in vouches:
            try:
                vouch_data = vouch.get("vouch", {})
                voucher_id = vouch_data.get("voucher_id")
                trust_level = vouch_data.get("trust_level", 1)
                
                points = TrustCalculator.VOUCH_WEIGHT * trust_level
                
                if voucher_id in my_trusted_contacts:
                    points *= TrustCalculator.TRUSTED_VOUCH_MULTIPLIER
                    details["vouches_from_trusted"] += 1
                
                score += points
                details["trust_level_sum"] += trust_level
            except Exception:
                continue
        
        # Calculate accusation penalty
        for accusation in accusations:
            try:
                proof_data = accusation.get("proof", {})
                accuser_id = proof_data.get("accuser_id")
                
                penalty = TrustCalculator.ACCUSATION_WEIGHT
                
                if accuser_id in my_trusted_contacts:
                    penalty *= TrustCalculator.TRUSTED_ACCUSATION_MULTIPLIER
                    details["accusations_from_trusted"] += 1
                
                score += penalty
            except Exception:
                continue
        
        details["final_score"] = score
        
        return score, details
    
    @staticmethod
    def get_trust_status(trust_score: int) -> str:
        """
        Get a human-readable trust status.
        
        Args:
            trust_score: Calculated trust score
            
        Returns:
            String status: "trusted", "neutral", "suspicious", "untrusted"
        """
        if trust_score >= 50:
            return "trusted"
        elif trust_score >= 0:
            return "neutral"
        elif trust_score >= -100:
            return "suspicious"
        else:
            return "untrusted"


class TrustManager:
    """
    Manages the Web of Trust system.
    
    Handles storage/retrieval of vouches and accusations in the DHT.
    """
    
    def __init__(self, kademlia_server):
        """
        Initialize TrustManager.
        
        Args:
            kademlia_server: Kademlia DHT server instance
        """
        self.kademlia_server = kademlia_server
    
    async def publish_vouch(self, vouch_with_signature: Dict) -> bool:
        """
        Publish a vouch to the DHT.
        
        Args:
            vouch_with_signature: Vouch dictionary with signature
            
        Returns:
            True if successful, False otherwise
        """
        try:
            vouch_data = vouch_with_signature["vouch"]
            vouched_id = vouch_data["vouched_id"]
            voucher_id = vouch_data["voucher_id"]
            timestamp = vouch_data["timestamp"]
            
            # Store vouch with key format: "vouch_{vouched_id}_{voucher_id}_{timestamp}"
            vouch_key = f"vouch_{vouched_id}_{voucher_id}_{timestamp}"
            await self.kademlia_server.set(vouch_key, json.dumps(vouch_with_signature))
            
            # Maintain an index of vouches for this user
            index_key = f"vouch_index_{vouched_id}"
            index_str = await self.kademlia_server.get(index_key)
            
            if index_str:
                index = json.loads(index_str)
            else:
                index = []
            
            index.append(vouch_key)
            await self.kademlia_server.set(index_key, json.dumps(index))
            
            return True
        except Exception:
            return False
    
    async def revoke_vouch(self, voucher_id: str, vouched_id: str) -> bool:
        """
        Revoke a previously published vouch.
        
        Args:
            voucher_id: ID of the voucher (you)
            vouched_id: ID of the vouched user
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Find vouches from this voucher to the vouched user
            index_key = f"vouch_index_{vouched_id}"
            index_str = await self.kademlia_server.get(index_key)
            
            if not index_str:
                return False
            
            index = json.loads(index_str)
            updated_index = []
            
            for vouch_key in index:
                # Check if this vouch is from the voucher
                if voucher_id in vouch_key:
                    # Skip this vouch (effectively removing it)
                    continue
                updated_index.append(vouch_key)
            
            await self.kademlia_server.set(index_key, json.dumps(updated_index))
            return True
        except Exception:
            return False
    
    async def get_vouches(self, user_id: str) -> List[Dict]:
        """
        Get all vouches for a user.
        
        Args:
            user_id: User ID to get vouches for
            
        Returns:
            List of vouch dictionaries
        """
        try:
            index_key = f"vouch_index_{user_id}"
            index_str = await self.kademlia_server.get(index_key)
            
            if not index_str:
                return []
            
            index = json.loads(index_str)
            vouches = []
            
            for vouch_key in index:
                vouch_str = await self.kademlia_server.get(vouch_key)
                if vouch_str:
                    vouch = json.loads(vouch_str)
                    vouches.append(vouch)
            
            return vouches
        except (KeyError, ValueError, json.JSONDecodeError):
            # Log the specific error for debugging
            # In production, this could be logged to a file
            return []
        except Exception:
            # Unexpected error - log for investigation
            # In production: logger.error(f"Unexpected error in get_vouches")
            return []
    
    async def publish_accusation(self, accusation_with_signature: Dict) -> bool:
        """
        Publish an accusation to the DHT.
        
        Args:
            accusation_with_signature: Accusation proof with signature
            
        Returns:
            True if successful, False otherwise
        """
        try:
            proof_data = accusation_with_signature["proof"]
            accused_id = proof_data["accused_id"]
            accuser_id = proof_data["accuser_id"]
            timestamp = proof_data["timestamp"]
            
            # Store accusation with key format: "accusation_{accused_id}_{accuser_id}_{timestamp}"
            accusation_key = f"accusation_{accused_id}_{accuser_id}_{timestamp}"
            await self.kademlia_server.set(accusation_key, json.dumps(accusation_with_signature))
            
            # Maintain an index of accusations for this user
            index_key = f"accusation_index_{accused_id}"
            index_str = await self.kademlia_server.get(index_key)
            
            if index_str:
                index = json.loads(index_str)
            else:
                index = []
            
            index.append(accusation_key)
            await self.kademlia_server.set(index_key, json.dumps(index))
            
            return True
        except Exception:
            return False
    
    async def get_accusations(self, user_id: str) -> List[Dict]:
        """
        Get all accusations against a user.
        
        Args:
            user_id: User ID to get accusations for
            
        Returns:
            List of accusation dictionaries
        """
        try:
            index_key = f"accusation_index_{user_id}"
            index_str = await self.kademlia_server.get(index_key)
            
            if not index_str:
                return []
            
            index = json.loads(index_str)
            accusations = []
            
            for accusation_key in index:
                accusation_str = await self.kademlia_server.get(accusation_key)
                if accusation_str:
                    accusation = json.loads(accusation_str)
                    accusations.append(accusation)
            
            return accusations
        except (KeyError, ValueError, json.JSONDecodeError):
            # Log the specific error for debugging
            # In production, this could be logged to a file
            return []
        except Exception:
            # Unexpected error - log for investigation
            # In production: logger.error(f"Unexpected error in get_accusations")
            return []
    
    async def calculate_user_trust(self, user_id: str, my_trusted_contacts: List[str] = None) -> Tuple[int, Dict]:
        """
        Calculate trust score for a user.
        
        Args:
            user_id: User to calculate trust for
            my_trusted_contacts: List of user IDs I trust
            
        Returns:
            Tuple of (trust_score, trust_details)
        """
        vouches = await self.get_vouches(user_id)
        accusations = await self.get_accusations(user_id)
        
        return TrustCalculator.calculate_trust_score(vouches, accusations, my_trusted_contacts)
