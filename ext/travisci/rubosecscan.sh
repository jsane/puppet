if [ "$CHECK" == "rubocop" ]; then 
	cd $TRAVIS_BUILD_DIR && rubocop --version
fi
