# Introduction
Python script to calculate users score based on their post engagement on a specific user for the last 20 posts. Any user just need to mention @mypostsinfo (my test account's username) to trigger the calculation and post the reply.

This script uses deso_sdk.py from https://github.com/deso-protocol/deso-python-sdk

# Attention
For this script you need the seed hex of the account you want to post the reply with the answer. Handle with care. Use this code at your own risk. Better create a seperate account with less amount just for the post fees.

## Features
1. comments
2. diamonds (diamondapp 💎 & Focus app 💎)
3. reposts
4. quote_reposts
5. reactions
6. polls
7. Follow

# Install required libraries
Needs Python3

python -m venv myenv

Linux:

source myenv/bin/activate

Windows:

myenv\Scripts\activate.bat

pip install -r requirements.txt


# Run the app
Last 20 posts

python notification_check_deso.py -p 20 -t 10

Last 7 days

python notification_check_deso.py -d 7 -t 10

# Help
usage: notification_check_deso.py [-h] [-p POSTS] [-d DAYS] [-t TOP]

Performs deso posts calculation

options:

  -h, --help            show this help message and exit
  
  -p POSTS, --posts POSTS Number of posts to check default="20"
                        
  -d DAYS, --days DAYS  past days  default="0" max days:365
  
  -t TOP, --top TOP     Top users limit default="10"
  
  
## How I measure post engagement
➕ Follow = 100pts

📢 Quote Repost = 25pts

🔄 Repost = 25pts

💬 First Commenter Bonus = 10pts

💬 Comment = 15pts

--💬 Sub 1 Comment = 15pts

—-💬 Sub 2 Comment = 15pts

📊 Poll = 10pts

❤️/👍/👎/😂/😮/😥/😠 = 1pt


Diamondapp

💎 Diamond Level 1 = 1pt

💎 Diamond Level 2 = 10pts

💎 Diamond Level 3 = 100pts

💎 Diamond Level 4 = 1,000pts

💎 Diamond Level 5 = 10,000pts

💎 Diamond Level 6 = 100,000pts


Focus App

💎 Diamond Level 1 = 10pts

💎 Diamond Level 2 = 100pts

💎 Diamond Level 3 = 1,000pts

💎 Diamond Level 4 = 10,000pts

💎 Diamond Level 5 = 100,000pts
