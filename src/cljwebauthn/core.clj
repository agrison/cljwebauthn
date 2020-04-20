(ns cljwebauthn.core
  (:require [clojure.data.json :as json]
            [cljwebauthn.b64 :as b64]
            [cljwebauthn.interop :as interop])
  (:import (java.util UUID)
           (com.webauthn4j.data AuthenticationRequest AuthenticationParameters)
           (com.webauthn4j WebAuthnManager)))

(def eliptic-curve -7)

(def ^:dynamic *challenges*
  (atom {:register {} :login {}}))

(defn generate-challenge
  "Generate a challenge for both registration and login."
  []
  (.toString (UUID/randomUUID)))


(defn decode-client-data
  "Decode the client data by parsing its JSON content."
  [data]
  (-> data b64/decode (json/read-str :key-fn keyword)))


;;; ----- registration
(defn prepare-registration
  "Prepare a user for registration by generating a challenge and
  giving the information needed by the browser to follow with the
  registration process.
  The `user-id` variable can be anything, it's usually an e-mail.
  The method will call the given can-register-user function before preparing
  for registration"
  ([user-id properties]
   (prepare-registration user-id (fn [user-id] true) properties))
  ([user-id can-register-user properties]
   (when (can-register-user user-id)
     (let [challenge (generate-challenge)]
       ; store the challenge for registration
       (swap! *challenges* assoc-in [:register challenge] user-id)
       ; give what's needed by the client for registration
       {:rp        {:id   (:site-id properties)
                    :name (:site-name properties)}
        :user      {:id (b64/encode user-id)}
        :cred      [{:type "public-key"
                     :alg  eliptic-curve}]
        :challenge challenge}))))

(defn register-user
  "Register a user given its attestation, client-data and challenge.
  The save authenticator function takes both the user-id and the authenticator
  to be saved so that it can be retrieved during login operation."
  [{:keys [attestation client-data challenge]}
   {:keys [protocol host port]}
   save-authenticator]
  (let [request (interop/->registration-request attestation client-data)
        parameters (interop/->registration-param protocol host port challenge)
        data (interop/->registration-data request)]
    (when (interop/registration-data-valid? data parameters)
      (let [user-id (get-in @*challenges* [:register challenge])]
        (save-authenticator user-id (interop/->authenticator data))
        {:user-id user-id :challenge challenge}))))

;;; ----- login
(defn prepare-login
  "Prepare user login using WebAuthn.
  Returns both a challenge and the credential-id used upon registration."
  [user-id get-authenticator]
  (let [challenge (generate-challenge)]
    (swap! *challenges* assoc-in [:login challenge] user-id)
    {:challenge   challenge
     :credentials [{:type "public-key",
                    :id   (-> (get-authenticator user-id)
                              .getAttestedCredentialData
                              .getCredentialId
                              b64/encode-binary)}]}))

(defn login-user
  "Login a user using Webauthn."
  [{:keys [credential-id user-handle authenticator-data client-data signature challenge]}
   {:keys [protocol host port]}
   get-authenticator]
  (let [authenticator (get-authenticator user-handle)
        ^AuthenticationRequest request (interop/->auth-request credential-id user-handle authenticator-data
                                                               client-data signature)
        ^AuthenticationParameters parameters (interop/->auth-parameters protocol host port challenge authenticator)
        ^WebAuthnManager manager (interop/default-manager)
        data (.parse manager request)]
    (when (.validate manager data parameters)
      {:user-id user-handle :challenge challenge})))