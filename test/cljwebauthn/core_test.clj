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

(deftest test-prepare-challenge
  (let [challenge "foobar"
        email "foo@bar.com"]
    (with-redefs [generate-challenge (fn [] challenge)]
      (let [prep (prepare-registration email site-properties)]
        (is (not (nil? prep)))
        (is (every? prep [:rp :user :cred :challenge]))
        (is (= {:rp        {:id (:site-id site-properties) :name (:site-name site-properties)}
                :user      {:id (b64/encode email)}
                :cred      [{:type "public-key" :alg -7}]
                :challenge challenge} prep))))))

(def register-payload
  {:attestation "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgeOSXUhr3sMAO2WVq/fzmqAJn5RSf00y+2JHWSnrfBH4CIQDX9OvQGKb5q8Fj/SgJuiT2HwAcxtJ2q1FaWugkfiY32mhhdXRoRGF0YVjF09CVCOxdEGxTwSc5mFMLk7vvUH763HGL3Wl3siTnwk1FXo81/q3OAAI1vMYKZIsLJfHwVQMAQQEZBainwiWsYFxuJud3Nst81qcUmRq4jdLB/sOo2EJxZbDa4vF+xh31DS+XYCw9/6Csm75edLI9yIffVJaree8lpQECAyYgASFYIO7qcEAfShtfCKN8k1hJ0Vo1GtJ3toA0+agxwJcu24xzIlggEfYFr083E++o65vZ/I8hCZ3+Jpd1FdbaqAkCY1nvQuI="
   :client-data "eyJjaGFsbGVuZ2UiOiJabTl2WW1GeSIsIm9yaWdpbiI6Imh0dHBzOi8vZ3Jpc29uLm1lIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
   :challenge   "foobar"})

(deftest test-register
  (let [challenge "foobar"
        auth (atom nil)
        user (register-user register-payload
                            site-properties
                            (fn [user-id authenticator]
                              (reset! auth authenticator)))]
    (is (= {:user-id "foo@bar.com" :challenge challenge} user))
    (is (not (nil? @auth)))))

(deftest test-prepare-login
  (let [email "foo@bar.com"
        auth (atom nil)]
    (with-redefs [generate-challenge (fn [] "foobar")]
      (let [_ (register-user register-payload site-properties
                             (fn [user-id authenticator] (reset! auth authenticator)))]
        (with-redefs [generate-challenge (fn [] "foobar2")]
          (let [prep (prepare-login email (fn [user-id] @auth))]
            (is (every? prep [:challenge :credentials]))
            (is (= "foobar2" (:challenge prep)))
            (is (every? (-> prep :credentials first) [:type :id]))))))))

(def login-payload
  {:credential-id      "ARkFqKfCJaxgXG4m53c2y3zWpxSZGriN0sH+w6jYQnFlsNri8X7GHfUNL5dgLD3/oKybvl50sj3Ih99Ulqt57yU="
   :user-handle        "Wm05dlFHSmhjaTVqYjIwPQ=="
   :authenticator-data "09CVCOxdEGxTwSc5mFMLk7vvUH763HGL3Wl3siTnwk0FXo82Tg=="
   :client-data        "eyJjaGFsbGVuZ2UiOiJabTl2WW1GeU1nIiwib3JpZ2luIjoiaHR0cHM6Ly9ncmlzb24ubWUiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0="
   :signature          "MEUCIQCkfqWpAhi7CRO0exa2wenWgDaakqJq2uUKpDix4UrlcQIgFeDV8HEki7WSjRkz4j+MVLBjypqBD8hSm7gv+gI1roY="
   :challenge          "foobar2"})

(deftest test-login
  (let [email "foo@bar.com"
        auth (atom nil)]
    (with-redefs [generate-challenge (fn [] "foobar")]
      (let [_ (register-user register-payload site-properties
                             (fn [user-id authenticator] (reset! auth authenticator)))
            user (login-user login-payload site-properties
                             (fn [user-id] @auth))]
        (is (every? user [:user-id :challenge]))
        (is (= "foobar2" (:challenge user)))
        (is (= email (b64/decode (b64/decode (:user-id user)))))))))