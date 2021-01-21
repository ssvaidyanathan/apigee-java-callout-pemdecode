# apigee-java-callout-pemdecode
- This is a sample Apigee proxy to decode a PEM payload using a [Java callout policy](https://docs.apigee.com/api-platform/reference/policies/java-callout-policy). 

- In this example, the pem is provided as a header ("pem" is the header name)

## Pre-Requisites

- Java 8 or later
- Maven 3.5 or later

## Steps

### Building the Jar

You do not need to build the Jar in order to use the custom policy. The custom policy is
ready to use, with policy configuration. You need to re-build the jar only if you want
to modify the behavior of the custom policy. Before you do that, be sure you understand
all the configuration options - the policy may be usable for you without modification.

If you do wish to build the jar, you can use
[maven](https://maven.apache.org/download.cgi) to do so. The build requires
JDK8. Before you run the build the first time, you need to download the Apigee
Edge dependencies into your local maven repo.

Preparation, first time only: `./buildsetup.sh`

#### To build: 
- Go to the `callout` directory
- Execute `mvn clean package`. This should create a jar called "original-edge-callout-pemdecode.jar" and also create a copy in `../bundle/apiproxy/resources/java` directory


### Deploy Apigee proxy
- Go to the `bundle` directory
- For SaaS/OPDK: Execute `mvn clean install -P{profile} -Dorg={org} -Dusername={username} -Dpassword={password} -f pom.xml`
- For hybrid: Execute `mvn clean install -Phybrid -Dorg={org} -Denv={env} -Dfile={file} -f pom-hybrid.xml`
- The above command should deploy the proxy as `apigee-pem-decode`. 
- To test, run the following curl
	```
		curl --location --request GET 'https://{host}/v1/pemdecode' \
            --header 'pem: {pem}'
	```
- All the decoded values will be available as flow variables which you can find via Trace tool.

## License

This code is released under the Apache Source License v2.0. For information see the [LICENSE](LICENSE) file.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

