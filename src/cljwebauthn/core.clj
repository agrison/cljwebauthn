(ns cljwebauthn.core
  (:require [clojure.data.json :as json]
            [cljwebauthn.b64 :as b64]
            [cljwebauthn.interop :as interop])
  (:import (java.util UUID)
           (com.webauthn4j.data AuthenticationRequest AuthenticationParameters)
           (com.webauthn4j WebAuthnManager)
           (com.webauthn4j.authenticator Authenticator)
           (com.webauthn4j.validator.exception BadSignatureException)))

(def eliptic-curve -7)

(def ^:dynamic *challenges*
  (atom {:register {} :login {}}))

(defn generate-challenge
  "Generate a challenge for both registration and login."
  []
  (str (UUID/randomUUID)))

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

  The method will call the given `can-register-user` function before preparing
  for registration.

  Example:
  ```clojure
  (prepare-registration
    \"foo@bar.com\"
    {:site-id   \"grison.me\",
     :site-name \"Stuff and Thoughts about IT Stuff\",
     :protocol  \"https\",
     :port      443,
     :host      \"grison.me\"})
=> {:rp        {:id  \"grison.me\"
                :name \"Stuff and Thoughts about IT Stuff\"}
    :user      {:id \"Zm9vQGJhci5jb20=\"}
    :cred      [{:type \"public-key\"
                 :alg  -7}]
    :challenge #uuid \"439cf387-25a9-40bc-a36a-bb84168e5f54\"}
  ```"
  ([user-id properties]
   (prepare-registration user-id (fn [_] true) properties))
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
  to be saved so that it can be retrieved during login operation.

  Example:
  ```clojure
  (register-user
    {:attestation \"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZ...dbaqAkCY1nvQuI=\"
     :client-data \"eyJjaGFsbGVuZ2UiOiJabTl2...ZWF0ZSJ9\"
     :challenge   \"439cf387-25a9-40bc-a36a-bb84168e5f54\"}
    {:site-id   \"grison.me\",
     :site-name \"Stuff and Thoughts about IT Stuff\",
     :protocol  \"https\",
     :port      443,
     :host      \"grison.me\"}
     (fn [user-id authenticator]
       ; save the authenticator for user-id somewhere
     ))
=> {:user-id \"foo@bar.com\" :challenge \"439cf387-25a9-40bc-a36a-bb84168e5f54\"}
   ```"
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

  Returns both a challenge and the credential-id used upon registration.

  Example:
  ```clojure
  (prepare-login
    \"foo@bar.com\"
    (fn [user-id]
      ; retrieve the authenticator(s) (one or more in a seq) for user-id
    ))
  => {:challenge   #uuid \"439cf387-25a9-40bc-a36a-bb84168e5f54\"
    :credentials [{:type \"public-key\"
                   :id   \"AWcH5uwgu/phBRUWh6B9A2...tg54nA==\"}]}
  ```"
  [user-id get-authenticator]
  (let [challenge (generate-challenge)]
    (when-let [authenticators (seq (get-authenticator user-id))]
      (swap! *challenges* assoc-in [:login challenge] user-id)
      {:challenge   challenge
       :credentials (for [^Authenticator authenticator authenticators]
                      {:type "public-key",
                       :id   (-> authenticator
                                 .getAttestedCredentialData
                                 .getCredentialId
                                 b64/encode-binary)})})))

(defn login-user
  "Login a user using Webauthn.

  Example:
  ```clojure
  (clogin-user
    {:credential-id      \"ARkFqKfCJaxgXG4m53c2y3zWpxSZGriN0sH...qt57yU=\"
     :user-handle        \"Zm9vQGJhci5jb20=\"
     :authenticator-data \"09CVCOxdEGxTwSc5mFML...3Wl3siTnwk0FXo82Tg==\"
     :client-data        \"eyJjaGFsbGVuZ2UiOiJabTl2WW1...G4uZ2V0In0=\"
     :signature          \"MEUCIQCkfqWpAhi7CRO0exa2wenWgDaakqJ..gv+gI1roY=\"
     :challenge          \"439cf387-25a9-40bc-a36a-bb84168e5f54\"}
   {:site-id   \"grison.me\",
     :site-name \"Stuff and Thoughts about IT Stuff\",
     :protocol  \"https\",
     :port      443,
     :host      \"grison.me\"}
   (fn [user-id]
      ; retrieve the authenticator(s) (one or more in a seq) associated with user-id
   ))
  => {:user-id \"foo@bar.com\" :challenge \"439cf387-25a9-40bc-a36a-bb84168e5f54\"}
  ```"
  [{:keys [credential-id user-handle authenticator-data client-data signature challenge]}
   {:keys [protocol host port]}
   get-authenticator]
  (let [^AuthenticationRequest request (interop/->auth-request credential-id user-handle authenticator-data
                                                               client-data signature)]
    (first (filter map?
                   (for [authenticator (get-authenticator user-handle)]
                     (let [^AuthenticationParameters parameters (interop/->auth-parameters
                                                                 protocol
                                                                 host
                                                                 port
                                                                 challenge
                                                                 authenticator)
                           ^WebAuthnManager manager (interop/default-manager)
                           data (.parse manager request)]
                       (try
                         (when (.validate manager data parameters)
                           {:user-id user-handle :challenge challenge})
                         (catch BadSignatureException _
                           ;; invalid assertion signature
                           nil))))))))
