<?php

class TelnyxSignature
{
  const DEFAULT_TOLERANCE = 300;

  /**
   * Verifies the signature header sent by Telnyx.
   *
   * Throws an Exception\SignatureVerificationException exception if the verification fails for any reason.
   * (Exceptions commented out in this version)
   *
   * @param string $payload the payload sent by Telnyx
   * @param string $signature_header the contents of the signature header sent by Telnyx
   * @param string $timestamp
   * @param string $public_key secret used to generate the signature
   * @param int $tolerance maximum difference allowed between the header's timestamp and the current time
   *
   * @return bool
   *
   * @throws SodiumException
   */
  public static function verifyHeader(string $payload, string $signature_header, string $timestamp, string $public_key, int $tolerance = self::DEFAULT_TOLERANCE) : bool
  {
    // Typecast timestamp to int for comparisons
    $timestamp = (int)$timestamp;

    // Check if timestamp is within tolerance
    if (($tolerance > 0) && (abs(time() - $timestamp) > $tolerance)) {
//      throw Exception\SignatureVerificationException::factory(
//          'Timestamp outside the tolerance zone',
//          $payload,
//          $signature_header
//      );
      return false;
    }

    // Convert base64 string to bytes for sodium crypto functions
    $public_key_bytes = base64_decode($public_key);
    $signature_header_bytes = base64_decode($signature_header);

    // Construct a message to test against the signature header using the timestamp and payload
    $signed_payload = $timestamp . '|' . $payload;

    if (!sodium_crypto_sign_verify_detached($signature_header_bytes, $signed_payload, $public_key_bytes)) {
//      throw Exception\SignatureVerificationException::factory(
//          'Signature is invalid and does not match the payload',
//          $payload,
//          $signature_header
//      );
      return false;
    }

    return true;
  }
}
