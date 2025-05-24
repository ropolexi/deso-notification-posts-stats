# Introduction
Python script to calculate user score based on post engagement via notification method

This script uses deso_sdk.py from https://github.com/deso-protocol/deso-python-sdk

## Features
1. comments
2. diamonds (diamondapp 💎 & Focus app 💎)
3. reposts
4. quote_reposts
5. reactions
6. polls
7. Follow

# Install required libraries
python3 -m venv myenv

source myenv/bin/activate

pip install -r requirements.txt

python3 deso_sdk.py

# Run the app
python notification_check_deso.py

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
