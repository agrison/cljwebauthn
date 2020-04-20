(ns cljwebauthn.b64
  (:import java.util.Base64))

(defn encode [^String to-encode]
  (.encodeToString (Base64/getEncoder) (.getBytes to-encode)))

(defn decode [^String to-decode]
  (String. (.decode (Base64/getDecoder) to-decode)))

(defn encode-binary [to-encode]
  (.encodeToString (Base64/getEncoder) to-encode))

(defn decode-binary [^String to-decode]
  (.decode (Base64/getDecoder) to-decode))