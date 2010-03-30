TARGETS=apport.jar crash.class crash.jar

all: $(TARGETS)

clean:
	rm -f $(TARGETS) com/ubuntu/apport/*.class

apport.jar: $(patsubst %.java,%.class,$(wildcard com/ubuntu/apport/*.java))

crash.jar: crash.class

%.class: %.java
	javac $^

%.jar:
	jar cvf $@ $^
