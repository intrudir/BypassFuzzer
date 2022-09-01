class SmartFilter():
    """ All credit for this filter goes to whoever did this:
    https://gist.github.com/defparam/8067cc4eb0140399f2bcd5f66a860db4
    """
    def __init__(self, repeats=10):
        # our data base to keep track of history
        self._db = {}
        # the number of repeats allowed before muting future responses
        self._repeats = repeats

    def check(self, status, wordlen):
        # We make a directory key by concating status code + number of words
        key = str(status)+str(wordlen)
        # if never seen this key before, add it to the dictionary with 1 hit
        if key not in self._db:
            self._db[key] = 1
        # if key exists and it reached the repeat maximum, mute the response
        elif self._db[key] >= self._repeats:
            return False
        # If the key hasn't reached the repeat limit,
        # add to the hit count and allow the response to be shown
        else:
            self._db[key] += 1

        return True