.PHONY: clean pkg deps

pkg:
	mvn --quiet package
	cp target/crsspy-1.0-SNAPSHOT.jar ../../inst/java
	cp deps/salvation-2.6.0.jar ../../inst/java

deps:
	mvn dependency:copy-dependencies -DoutputDirectory=deps

clean:
	mvn clean

new:
	mvn archetype:generate -DgroupId=is.rud.crsspy -DartifactId=crsspy -DarchetypeArtifactId=maven-archetype-quickstart -DarchetypeVersion=1.4 -DinteractiveMode=false