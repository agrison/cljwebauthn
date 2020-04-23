(ns cljwebauthn.b64
  (:import java.util.Base64))

(defn encode
  "Base64 encode the given String."
  [^String to-encode]
  (.encodeToString (Base64/getEncoder) (.getBytes to-encode)))

(defn decode
  "Base64 decode the given String."
  [^String to-decode]
  (String. (.decode (Base64/getDecoder) to-decode)))

(defn encode-binary
  "Base64 encode the given byte array."
  [^bytes to-encode]
  (.encodeToString (Base64/getEncoder) to-encode))

(defn decode-binary
  "Base64 decode the given String to a byte array."
  [^String to-decode]
  (.decode (Base64/getDecoder) to-decode))