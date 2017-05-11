if [ "$CHECK" == "rubocop" ]; then 
	# TODO:: 
	# Install the latest version of rubocop only if needed (and not already installed)
	gem install rubocop     # This should get the latest and greatest version 
	echo `rubocop --version`
	cd $TRAVIS_BUILD_DIR && rubocop
fi
