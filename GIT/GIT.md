[!] `git commit`
```bash
git add -all
git add		#add files to staging area
git status 	#show untracked files in a repo
git commit -m "Message goes here"	# -m flag stands for message
git commit -am "Message" # commit all files with message "Message"
git ls-files		 # files in staging area
git rm filename.txt	# removes file both from staging area and working dir
```

[!] `git mv`
```bash
mv file1.txt main.js
git status
	deleted: file1.txt
	untracked: main.jx
	
git add file1.txt
git add main.js
git status
	renamed: file1.txt -> main.js
```

```bash
git mv main.js file1.js	# changes appiled both to staging area and working dir
```

[!] `.gitingonre`
```bash
mkdir logs
echo hello > logs/dev.logs

git status
	untracked:
		logs/
echo logs/ > .gitignore	# add dir or files to ignore
# Following changes to logs/ will not be tracked.
```

Add `files` and `directories` to `.gitignore` only before creating them 
Because if file already existing and committed, it is present in the staging area, meaning that it will be tracked anyway. To prevent this delete it from the index.

```bash
git rm --cached -r 	# remove dir only from index (staged area)
```

```bash
git status -s	# short version
			M (green) - modified and added to staging area
			M (red)   - modified but not added
			?? - new file created
			A - file added to staging area
```

```bash
git push -u origin main	#this command makes site appear somehow.
```

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

key must be not fine grained
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

```bash
gh auth login
# -> select web login via ssh
# -> ssh keys will be generated
git remote show origin

git remote set-url origin git+ssh://git@github.com/allsaint/allsaint.github.io.git
git init -b main    #create main branch could be called master or whatever
git branch
gh repo create
git remote add origin git@github.comallsaint:allsaint.github.io.git

```