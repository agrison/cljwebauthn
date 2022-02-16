(ns cljwebauthn.core-test
  (:require [clojure.test :refer :all]
            [cljwebauthn.core :refer :all]
            [cljwebauthn.b64 :as b64]))

(def site-properties
  {:site-id   "grison.me",
   :site-name "Stuff and Thoughts about IT Stuff",
   :protocol  "https",
   :port      443,
   :host      "grison.me"})

(def REGISTER-CHALLENGE "foobar")
(def LOGIN-CHALLENGE "foobar2")
(def EMAIL "foo@bar.com")

(deftest test-prepare-challenge
  (with-redefs [generate-challenge (fn [] REGISTER-CHALLENGE)]
    (let [prep (prepare-registration EMAIL site-properties)]
      (is (not (nil? prep)))
      (is (every? prep [:rp :user :cred :challenge]))
      (is (= {:rp        {:id (:site-id site-properties) :name (:site-name site-properties)}
              :user      {:id (b64/encode EMAIL)}
              :cred      [{:type "public-key" :alg -7}]
              :challenge REGISTER-CHALLENGE} prep))
      (is (contains? (:register @*challenges*) REGISTER-CHALLENGE)))))

(def register-payload
  {:attestation "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgeOSXUhr3sMAO2WVq/fzmqAJn5RSf00y+2JHWSnrfBH4CIQDX9OvQGKb5q8Fj/SgJuiT2HwAcxtJ2q1FaWugkfiY32mhhdXRoRGF0YVjF09CVCOxdEGxTwSc5mFMLk7vvUH763HGL3Wl3siTnwk1FXo81/q3OAAI1vMYKZIsLJfHwVQMAQQEZBainwiWsYFxuJud3Nst81qcUmRq4jdLB/sOo2EJxZbDa4vF+xh31DS+XYCw9/6Csm75edLI9yIffVJaree8lpQECAyYgASFYIO7qcEAfShtfCKN8k1hJ0Vo1GtJ3toA0+agxwJcu24xzIlggEfYFr083E++o65vZ/I8hCZ3+Jpd1FdbaqAkCY1nvQuI="
   :client-data "eyJjaGFsbGVuZ2UiOiJabTl2WW1GeSIsIm9yaWdpbiI6Imh0dHBzOi8vZ3Jpc29uLm1lIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
   :challenge   REGISTER-CHALLENGE})

(deftest test-register
  (with-redefs [generate-challenge (fn [] REGISTER-CHALLENGE)]
    (let [auth (atom nil)
          _ (prepare-registration EMAIL site-properties)
          user (register-user register-payload
                              site-properties
                              (fn [user-id authenticator]
                                (println "Registering user " user-id)
                                (reset! auth authenticator)))
          auth-value @auth]
      (is (contains? (:register @*challenges*) REGISTER-CHALLENGE))
      (is (= {:user-id EMAIL :challenge REGISTER-CHALLENGE} user))
      (is (not (nil? auth-value))))))

(deftest test-prepare-login
  (let [auth (atom nil)]
    (with-redefs [generate-challenge (fn [] REGISTER-CHALLENGE)]
      (let [_ (prepare-registration EMAIL site-properties)
            _ (register-user register-payload site-properties
                             (fn [user-id authenticator]
                               (println "Registering user" user-id)
                               (reset! auth authenticator)))]
        (with-redefs [generate-challenge (fn [] LOGIN-CHALLENGE)]
          (let [prep (prepare-login EMAIL (fn [user-id] [@auth]))]
            (is (contains? (:login @*challenges*) LOGIN-CHALLENGE))
            (is (every? prep [:challenge :credentials]))
            (is (= LOGIN-CHALLENGE (:challenge prep)))
            (is (every? (-> prep :credentials first) [:type :id]))))))))

(def login-payload
  {:credential-id      "ARkFqKfCJaxgXG4m53c2y3zWpxSZGriN0sH+w6jYQnFlsNri8X7GHfUNL5dgLD3/oKybvl50sj3Ih99Ulqt57yU="
   :user-handle        "Wm05dlFHSmhjaTVqYjIwPQ=="
   :authenticator-data "09CVCOxdEGxTwSc5mFMLk7vvUH763HGL3Wl3siTnwk0FXo82Tg=="
   :client-data        "eyJjaGFsbGVuZ2UiOiJabTl2WW1GeU1nIiwib3JpZ2luIjoiaHR0cHM6Ly9ncmlzb24ubWUiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0="
   :signature          "MEUCIQCkfqWpAhi7CRO0exa2wenWgDaakqJq2uUKpDix4UrlcQIgFeDV8HEki7WSjRkz4j+MVLBjypqBD8hSm7gv+gI1roY="
   :challenge          LOGIN-CHALLENGE})

(deftest test-login
  (let [auth (atom nil)]
    (with-redefs [generate-challenge (fn [] REGISTER-CHALLENGE)]
      (let [_ (prepare-registration EMAIL site-properties)
            _ (register-user register-payload site-properties
                             (fn [user-id authenticator]
                               (println "Registering user" user-id)
                               (reset! auth authenticator)))
            user (login-user login-payload site-properties
                             (fn [user-id] [@auth]))]
        (is (every? user [:user-id :challenge]))
        (is (= LOGIN-CHALLENGE (:challenge user)))
        (is (= EMAIL (b64/decode (b64/decode (:user-id user)))))))))
