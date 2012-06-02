This is a stand-alone web application that allows you to easily
generate a Certificate Signing Request for using the Identity
service. The application will also generate a private key and a secret
key to encrypt the private key. It is important for you to perform
these operations yourself so that the private key and secret key are
not known to anyone but yourself.

To build the application you need [Maven](http://maven.apache.org/download.html). Then you can do:

    mvn -D jetty.port=8837 jetty:run

Which starts the web application on port 8837. Then using any browser, goto [http://localhost:8837](http://localhost:8837).

Whatever directory you build the application in and run mvn in, is the
directory the generated files will be saved to. After completing the
process you should have three additional files i.e. identity.csr.pem,
identity.key.pem and secret.key. Mail the identity.csr.pem with the
email link provided. Keep the identity.key.pem and secret.key safe and
secure and continue with any further integration steps that may be
required.

