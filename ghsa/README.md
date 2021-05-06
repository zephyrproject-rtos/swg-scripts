# Using the ghsa tools.

In order to use this tool, you will need active cookies for a live
session to github.  These can be saved with something such as "Save
Cookies" in Firefox.

To use this, navigate to github, and make sure you are logged in.
Select the Save Cookies addon, and save the cookies for github.com.
You should end up with a file `cookies-github-com.txt`.  Pass this
into the script with something like:

```
./ghsa.py --mozilla-cookies cookies-github-com.txt
```

TODO: Write instructions for Chrome.
