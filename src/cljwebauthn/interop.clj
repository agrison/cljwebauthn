(ns cljwebauthn.interop
  (:require [cljwebauthn.b64 :as b64])
  (:import (com.webauthn4j.server ServerProperty)
           (com.webauthn4j.data RegistrationRequest RegistrationParameters AuthenticationRequest RegistrationData AuthenticationParameters)
           (com.webauthn4j.data.client.challenge DefaultChallenge)
           (com.webauthn4j WebAuthnManager)
           (com.webauthn4j.data.client Origin)
           (com.webauthn4j.authenticator AuthenticatorImpl)))

(defn ->registration-request
  "Makes a Webauthn4J **RegistrationRequest**.

  `attestation` and `client-data` are expected to be base64 encoded byte-array."
  [^bytes attestation ^bytes client-data]
  (RegistrationRequest.
   (b64/decode-binary attestation)
   (b64/decode-binary client-data)
   nil
   #{}))

(defn ->server-property
  "Makes a Webauthn4J **ServerProperty**.

  `protocol` is either `http` or `https`."
  [^String protocol ^String host ^Integer port ^String challenge]
  (ServerProperty. (Origin. (str protocol "://" host ":" port))
                   host
                   (DefaultChallenge. ^String (b64/encode challenge))
                   (byte-array 0)))

(defn ->registration-param
  "Makes a Webauthn4J **RegistrationParameters**.

  `protocol` is either `http` or `https`."
  [^String protocol ^String host ^Integer port ^String challenge]
  (RegistrationParameters.
   (->server-property protocol host port challenge)
   nil false true))

(defn ->registration-data
  "Makes a Webauthn4J **WebAuthnManager**."
  [^RegistrationRequest request]
  (.parse (WebAuthnManager/createNonStrictWebAuthnManager) request))

(defn default-manager
  "Creates a default **WebAuthnManager**."
  []
  (WebAuthnManager/createNonStrictWebAuthnManager))

(defn registration-data-valid?
  "Returns whether the given registration date is valid."
  [^RegistrationData data ^RegistrationParameters parameters]
  (try
    (.validate ^WebAuthnManager (default-manager) data parameters)
    true
    (catch Exception _ false)))

(defn ->authenticator
  "Makes a Webauthn4J **AuthenticatorImpl**."
  [^RegistrationData data]
  (AuthenticatorImpl/createFromRegistrationData data))

(defn ->auth-request
  "Makes a Webauthn4j **AuthenticationRequest**.

  All the parameters are expected to be base64 encoded byte-arrays."
  [^bytes credential-id ^bytes user-handle ^bytes authenticator-data ^bytes client-data ^bytes signature]
  (AuthenticationRequest.
   (b64/decode-binary credential-id)
   (b64/decode-binary user-handle)
   (b64/decode-binary authenticator-data)
   (b64/decode-binary client-data)
   nil
   (b64/decode-binary signature)))

(defn ->auth-parameters
  "Makes a Webauthn4j **AuthenticationParameters**."
  [^String protocol ^String host ^Integer port ^String challenge ^AuthenticatorImpl authenticator]
  (AuthenticationParameters.
   (->server-property protocol host port challenge)
   authenticator
   nil false true))
