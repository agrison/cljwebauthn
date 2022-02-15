# WebAuthn for Clojure

[![cljdoc badge](https://cljdoc.org/badge/me.grison/cljwebauthn)](https://cljdoc.org/d/me.grison/cljwebauthn/CURRENT)

This library give you a Clojure wrapper over WebAuthn4J so that you can enable user registration and login functionality through WebAuthn in your Clojure backend / API.

Its API is composed of 4 functions for:

- preparing a registration challenge
- register a user given the browser generated credentials
- preparing a login challenge
- login a user given the browser generated signature

[![Alt text](https://img.youtube.com/vi/Q_2O13_yST4/0.jpg)](https://www.youtube.com/watch?v=Q_2O13_yST4)

Current version of cljwebauthn uses version webauthn4j-core-0.19.0.RELEASE.

## Dependency

Add the following dependency:

```xml
<dependency>
   <groupId>me.grison</groupId>
   <artifactId>cljwebauthn</artifactId>
   <version>0.1.3</version>
</dependency>
```

**deps.edn**
```clojure
me.grison/cljwebauthn {:mvn/version "0.1.3"}
```

**Leiningen/Boot**
```clojure
[me.grison/cljwebauthn "0.1.2"]
```

## API

### `(prepare-registration user-identifier site-properties)`

This function will prepare a registration challenge for the client.

- **input** 
  - **user-identifier**: can be anything that can identify a user, like an email or a nickname.
  - **site-properties**: a map containing at least the following entries:
    - **:site-id**: your website identifier (`grison.me`)
    - **:site-name**: your website tagline (`My personal website`)
    - **:protocol**: either `http` or `https`
    - **:port**: the port your site is running on (`80`, `443`, ...)
    - **:host**: your website hostname (`grison.me`)
- **output**
    - the necessary information needed on client side to bootstrap the navigator credentials

Example:
```clojure
(cljwebauthn.core/prepare-registration 
    "foo@bar.com" 
    {:site-id   "grison.me",
     :site-name "Stuff and Thoughts about IT Stuff",
     :protocol  "https",
     :port      443,
     :host      "grison.me"})
=> {:rp        {:id  "grison.me"
                :name "Stuff and Thoughts about IT Stuff"}
    :user      {:id "Zm9vQGJhci5jb20="}
    :cred      [{:type "public-key"
                 :alg  -7}]
    :challenge challenge}
```



### `(register-user attestation site-properties save-authenticator)`

This function will validate the attestations generated by the client and call the `save-authenticator` function on success so that the API user can save the WebAuthn4J **authenticator** object for usage later on.

- **input** 
  - **attestation**: a map containing at least the following entries:
    - **:attestation**: base64 encoded value of the credential public key, an optional attestation certificate, and other metadata used also to validate the registration event. 
    - **:client-data**: base64 encoded value of the data passed from the browser to the authenticator in order to associate the new credential with the server and browser.
    - **:challenge**: the challenge generated during the `prepare-registration` phase.
  - **site-properties**: a map containing at least the following entries:
    - **:site-id**: your website identifier (`grison.me`)
    - **:site-name**: your website tagline (`My personal website`)
    - **:protocol**: either `http` or `https`
    - **:port**: the port your site is running on (`80`, `443`, ...)
    - **:host**: your website hostname (`grison.me`)
  - **save-authenticator**: a function whose job is to save the WebAuthn4J authenticator object, taking two parameters
    - **user-id**: the user identifier
    - **authenticator**: the WebAuthn4J authenticator object
- **output**
    - a map containing the user-identifier and the challenge in case of success
    - `nil` in case the registration wasn't successful

Example:
```clojure
(cljwebauthn.core/register-user 
    {:attestation "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZ...dbaqAkCY1nvQuI="
     :client-data "eyJjaGFsbGVuZ2UiOiJabTl2...ZWF0ZSJ9"
     :challenge   "foobar"}
    {:site-id   "grison.me",
     :site-name "Stuff and Thoughts about IT Stuff",
     :protocol  "https",
     :port      443,
     :host      "grison.me"}
     (fn [user-id authenticator] 
       ; save the authenticator for user-id somewhere
     ))
=> {:user-id "foo@bar.com" :challenge "foobar"} 
```


### `(prepare-login user-identifier get-authenticator)`

This function will prepare a login challenge for the client.

- **input** 
  - **user-identifier**: can be anything that can identify a user, like an email or a nickname.
  - **get-authenticator**: a function whose job is to retrieve the authenticator previously saved WebAuthn4J authenticator object.
- **output**
    - the necessary information needed on client side to bootstrap the navigator credentials

Example:
```clojure
(cljwebauthn.core/prepare-login 
    "foo@bar.com" 
    (fn [user-id]
      ; retrieve the authenticator for user-id
    ))
=> {:challenge   "foobar"
    :credentials [{:type "public-key"
                   :id   "AWcH5uwgu/phBRUWh6B9A2...tg54nA=="}]}
```



### `(login-user assertion site-properties get-authenticator)`

This function will prepare a login challenge for the client.

- **input** 
  - **assertion**: a map containing at least the following entries:
    - **:credential-id**: base64 encoded value of the navigator credential raw id
    - **:user-handle**: base64 encoded value of the user identifier
    - **:authenticator-data**: base64 encoded value of the authenticator data which is similar to the authData received during registration, with the notable exception that the public key is not included here. It is another item used during authentication as source bytes to generate the assertion signature.
    - **:client-data**: base64 encoded value of a collection of the data passed from the browser to the authenticator. It is one of the items used during authentication as the source bytes to generate the signature.
    - **:signature**: base64 encoded value of the signature generated by the private key associated with this credential. 
    - **:challenge**: the challenge generated during the `prepare-login` phase. 
  - **site-properties**: a map containing at least the following entries:
    - **:site-id**: your website identifier (`grison.me`)
    - **:site-name**: your website tagline (`My personal website`)
    - **:protocol**: either `http` or `https`
    - **:port**: the port your site is running on (`80`, `443`, ...)
    - **:host**: your website hostname (`grison.me`)
  - **get-authenticator**: a function whose job is to retrieve the authenticator previously saved WebAuthn4J authenticator object.
- **output**
    - a map containing the user-identifier and the challenge in case of success
    - `nil` in case the registration wasn't successful

```clojure
(cljwebauthn.core/login-user
    {:credential-id      "ARkFqKfCJaxgXG4m53c2y3zWpxSZGriN0sH...qt57yU="
     :user-handle        "Zm9vQGJhci5jb20="
     :authenticator-data "09CVCOxdEGxTwSc5mFML...3Wl3siTnwk0FXo82Tg=="
     :client-data        "eyJjaGFsbGVuZ2UiOiJabTl2WW1...G4uZ2V0In0="
     :signature          "MEUCIQCkfqWpAhi7CRO0exa2wenWgDaakqJ..gv+gI1roY="
     :challenge          "foobar"}
   {:site-id   "grison.me",
     :site-name "Stuff and Thoughts about IT Stuff",
     :protocol  "https",
     :port      443,
     :host      "grison.me"}  
   (fn [user-id] 
      ; retrieve the authenticator associated with user-id
   ))
=> {:user-id "foo@bar.com" :challenge "foobar"} 
```

## Testing

### Running tests:

```bash
clj -M:test
```

### Running the sample test app:

```bash
clj -M:run-test
```

Then open [http://localhost:8080](http://localhost:8080).



