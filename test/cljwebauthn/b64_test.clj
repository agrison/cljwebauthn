(ns cljwebauthn.b64-test
  (:require [clojure.test :refer :all]
            [cljwebauthn.b64 :refer :all]))

(deftest test-encode-string
  (is (= "Zm9vYmFy" (encode "foobar"))))

(deftest test-decode-string
  (is (= "foobar" (decode "Zm9vYmFy"))))

(deftest test-encode-binary
  (is (= "Zm9vYmFy" (encode-binary (.getBytes "foobar")))))
