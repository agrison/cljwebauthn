(ns cljwebauthn.sample-app-test
  (:gen-class)
  (:require [clojure.test :refer :all]
            [cljwebauthn.core :as webauthn]
            [buddy.auth.accessrules :refer [restrict IRuleHandlerResponse]]
            [buddy.auth.backends.session :refer [session-backend]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]]
            [buddy.hashers :as hashers]
            [clojure.java.io :as io]
            [compojure.core :refer [defroutes context GET POST]]
            [ring.adapter.jetty :refer [run-jetty]]
            [ring.middleware.session :refer [wrap-session]]
            [ring.middleware.params :refer [wrap-params]]
            [ring.util.response :refer [response redirect]]
            [clojure.data.json :as json])
  (:import (java.util UUID)))

;; sample database
(def database (atom {}))

;; user management
(defn register-user! [email authenticator]
  (let [user {:id (UUID/randomUUID) :email email :authenticator authenticator}]
    (swap! database assoc email user)))

(defn get-user [email]
  (get @database email))

;; Templates
(defn home-page [_]
  (slurp (io/resource "index.html")))

(defn register-page [_]
  (slurp (io/resource "register.html")))

(defn login-page [_]
  (slurp (io/resource "login.html")))

(defn admin-page [req]
  (slurp (io/resource "admin.html")))

(defn do-logout [{session :session}]
  (assoc (redirect "/login")
    :session (dissoc session :identity)))

;; data sample
(def site-properties
  {:site-id   "grison.me",
   :site-name "Stuff and Thoughts about IT Stuff",
   :protocol  "https",
   :port      443,
   :host      "grison.me"})

(def REGISTER-CHALLENGE "foobar")
(def LOGIN-CHALLENGE "foobar2")
(def EMAIL "foo@bar.com")
(def register-payload
  {:attestation "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgeOSXUhr3sMAO2WVq/fzmqAJn5RSf00y+2JHWSnrfBH4CIQDX9OvQGKb5q8Fj/SgJuiT2HwAcxtJ2q1FaWugkfiY32mhhdXRoRGF0YVjF09CVCOxdEGxTwSc5mFMLk7vvUH763HGL3Wl3siTnwk1FXo81/q3OAAI1vMYKZIsLJfHwVQMAQQEZBainwiWsYFxuJud3Nst81qcUmRq4jdLB/sOo2EJxZbDa4vF+xh31DS+XYCw9/6Csm75edLI9yIffVJaree8lpQECAyYgASFYIO7qcEAfShtfCKN8k1hJ0Vo1GtJ3toA0+agxwJcu24xzIlggEfYFr083E++o65vZ/I8hCZ3+Jpd1FdbaqAkCY1nvQuI="
   :client-data "eyJjaGFsbGVuZ2UiOiJabTl2WW1GeSIsIm9yaWdpbiI6Imh0dHBzOi8vZ3Jpc29uLm1lIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
   :challenge   REGISTER-CHALLENGE})
(def login-payload
  {:credential-id      "ARkFqKfCJaxgXG4m53c2y3zWpxSZGriN0sH+w6jYQnFlsNri8X7GHfUNL5dgLD3/oKybvl50sj3Ih99Ulqt57yU="
   :user-handle        "Zm9vQGJhci5jb20="
   :authenticator-data "09CVCOxdEGxTwSc5mFMLk7vvUH763HGL3Wl3siTnwk0FXo82Tg=="
   :client-data        "eyJjaGFsbGVuZ2UiOiJabTl2WW1GeU1nIiwib3JpZ2luIjoiaHR0cHM6Ly9ncmlzb24ubWUiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0="
   :signature          "MEUCIQCkfqWpAhi7CRO0exa2wenWgDaakqJq2uUKpDix4UrlcQIgFeDV8HEki7WSjRkz4j+MVLBjypqBD8hSm7gv+gI1roY="
   :challenge          LOGIN-CHALLENGE})

;; Webauthn handlers
(defn do-prepare-register [req]
  (-> req
      (get-in [:params "email"])
      (webauthn/prepare-registration site-properties)
      clojure.data.json/write-str
      response))

(defn input [body]
  (if (instance? String body)
     body
     (slurp body)))

(defn do-register [req]
  (let [payload (-> req :body input (json/read-str :key-fn keyword))]
    (if-let [user (webauthn/register-user payload site-properties register-user!)]
      (ring.util.response/created "/login" (json/write-str user))
      (ring.util.response/status 500))))

(defn do-prepare-login [req]
  (let [email (get-in req [:params "email"])]
    (if-let [resp (webauthn/prepare-login email (fn [email] (:authenticator (get-user email))))]
      (response (json/write-str resp))
      (ring.util.response/status
        (json/write-str {:message (str "Cannot prepare login for user: " email)}) 500))))

(defn do-login [{session :session :as req}]
  (let [payload (-> req :body input (json/read-str :key-fn keyword))]
    (let [email (cljwebauthn.b64/decode (:user-handle payload))
          user (get-user email)
          auth (:authenticator user)]
      (if-let [log (webauthn/login-user payload site-properties (fn [email] auth))]
        (assoc (redirect "/") :session (assoc session :identity (select-keys user [:id :email])))
        (redirect "/login")))))

;; Auth
(defn is-authenticated [{:keys [user]}]
  (not (nil? user)))

(defn wrap-user [handler]
  (fn [{identity :identity :as req}]
    (handler (assoc req :user (get-user (:email identity))))))


;; Routes
(defroutes admin-routes
           (GET "/" [] admin-page))

(defroutes all-routes
           (context "/admin" []
             (restrict admin-routes {:handler is-authenticated}))
           (GET "/" [] home-page)
           (GET "/register" [] register-page)
           (GET "/login" [] login-page)
           (GET "/logout" [] do-logout)
           (context "/webauthn" []
             (GET "/register" [] do-prepare-register)
             (POST "/register" [] do-register)
             (GET "/login" [] do-prepare-login)
             (POST "/login" [] do-login)))

(def my-app
  (let [backend (session-backend)]
    (-> #'all-routes
        (wrap-user)
        (wrap-authentication backend)
        (wrap-authorization backend)
        (wrap-session)
        (wrap-params))))

(defn -main []
  (with-redefs [site-properties
                {:site-id   "localhost",
                 :site-name "There's no place like home",
                 :protocol  "http",
                 :port      8080,
                 :host      "localhost"}]
    (run-jetty my-app {:port 8080 :host "localhost"})))

(deftest test-valid-app
  (let [pre-register (with-redefs [webauthn/generate-challenge (fn [] "foobar")]
                       (my-app {:request-method :get :uri "/webauthn/register" :params {"email" "foo@bar.com"}}))
        register (my-app {:request-method :post :uri "/webauthn/register" :body (json/write-str register-payload)})
        pre-login (with-redefs [webauthn/generate-challenge (fn [] "foobar2")]
                    (my-app {:request-method :get :uri "/webauthn/login" :params {"email" "foo@bar.com"}}))
        login (my-app {:request-method :post :uri "/webauthn/login" :body (json/write-str login-payload)})
        cookie (-> login (get-in [:headers "Set-Cookie"]) first (clojure.string/split #";") first)
        admin (my-app {:request-method :get :uri "/admin" :headers {"cookie" cookie}})]
    (prn pre-register)
    (is (= 200 (:status pre-register)))
    (prn register)
    (is (= 201 (:status register)))
    (prn pre-login)
    (is (= 200 (:status pre-login)))
    (prn login)
    (is (= 302 (:status login)))
    (is (= "/" (get-in login [:headers "Location"])))
    (is (not (nil? cookie)))
    (prn admin)
    (is (= 200 (:status admin)))
    (is (clojure.string/includes? admin "You have access to the protected page."))))