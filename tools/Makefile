CXX = g++
CXX_FLAGS = -std=c++11 -Wall -Werror

all: ./bin/aucont_exec ./bin/aucont_list ./bin/aucont_start ./bin/aucont_stop

./bin/%: ./src/%.cpp ./src/utils.h
	$(CXX) $(CXX_FLAGS) $< -o $@

clean:
	rm -f ./bin/*

.PHONY: all clean
