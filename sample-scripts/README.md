`example-test-scripts` is just for demonstration so that you can play around with the demo tests out of box. For production environment, you will probably have your own test assets. Same for `robot-test-endpoint`, implement your own work of test endpoint along with the test scripts in a stand-alone repository as they're coupled to work together.

By this way you can keep tracking the latest code of auto test framework without the pain of messing with the code here by the frequent changes of test scripts.

Notice: please modify environment variables in the `config.py` to point to the right places after setting up your test asset repository.