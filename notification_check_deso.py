import requests
import json
import threading  # For background calculations
import concurrent.futures
import time
from deso_sdk import DeSoDexClient
from deso_sdk  import base58_check_encode
import argparse
from pprint import pprint
import datetime
import re

blacklist = ["greenwork32","globalnetwork22"]  #bots accounts username list

BASE_URL = "https://node.deso.org"

REMOTE_API = False
HAS_LOCAL_NODE_WITH_INDEXING = False
HAS_LOCAL_NODE_WITHOUT_INDEXING = True

seed_phrase_or_hex="" #dont share this

COMMENT_SCORE = 15
FIRST_COMMENT_SCORE = 10
REPOST_SCORE = 25
QUOTE_REPOST_SCORE = 25
FOLLOW_SCORE = 100
LIKE_SCORE = 1
POLL_SCORE = 10

NOTIFICATION_UPDATE_INTERVEL = 30 #in seconds

like_types = ["LIKE", "LOVE", "DISLIKE", "SAD", "ASTONISHED", "ANGRY", "LAUGH"]
api_url = BASE_URL+"/api/v0/"
local_url= "http://localhost"+"/api/v0/"
prof_resp="PublicKeyToProfileEntryResponse"
tpkbc ="TransactorPublicKeyBase58Check"
pkbc="PublicKeyBase58Check"

# Global variables for thread control
stop_flag = True
calculation_thread = None
app_close=False

if REMOTE_API:
    HAS_LOCAL_NODE_WITHOUT_INDEXING= False
    HAS_LOCAL_NODE_WITH_INDEXING = False
else:
    if HAS_LOCAL_NODE_WITHOUT_INDEXING:
        HAS_LOCAL_NODE_WITH_INDEXING = False

    if HAS_LOCAL_NODE_WITH_INDEXING:
        HAS_LOCAL_NODE_WITHOUT_INDEXING = False

print(f"HAS_LOCAL_NODE_WITHOUT_INDEXING:{HAS_LOCAL_NODE_WITHOUT_INDEXING}")
print(f"HAS_LOCAL_NODE_WITH_INDEXING:{HAS_LOCAL_NODE_WITH_INDEXING}")


client = DeSoDexClient(
    is_testnet=False,
    seed_phrase_or_hex=seed_phrase_or_hex,
    passphrase="",
    node_url=BASE_URL
)

def api_get(endpoint, payload=None):
    try:
        if REMOTE_API:
            response = requests.post(api_url + endpoint, json=payload)
        else:
            if HAS_LOCAL_NODE_WITHOUT_INDEXING:
                if endpoint=="get-notifications":
                    print("---Using remote node---")
                    response = requests.post(api_url + endpoint, json=payload)
                    print("--------End------------")
                else:
                    response = requests.post(local_url + endpoint, json=payload)
            if HAS_LOCAL_NODE_WITH_INDEXING:
                response = requests.post(local_url + endpoint, json=payload)
            
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"API Error: {e}")
        return None

def get_single_profile(Username,PublicKeyBase58Check=""):
    payload = {
        "NoErrorOnMissing": False,
        "PublicKeyBase58Check": PublicKeyBase58Check,
        "Username": Username
    }
    data = api_get("get-single-profile", payload)
    return data


bot_public_key = base58_check_encode(client.deso_keypair.public_key, False)
bot_username = get_single_profile("",bot_public_key)["Profile"]["Username"]
if bot_username is None:
    print("Error,bot username can not get. exit")
    exit()


def post_associations_counts(post_hash,AssociationType,AssociationValues):
    payload = {
        "AssociationType": AssociationType,
        "AssociationValues": AssociationValues,
        "PostHashHex": post_hash
    }
    data = api_get("post-associations/counts", payload)
    return data

def get_post_associations(post_hash, AssociationType,AssociationValue):
    payload = {
        "AssociationType": AssociationType,
        "AssociationValue": AssociationValue,
        "IncludeTransactorProfile": True,
        "Limit": 100,
        "PostHashHex": post_hash
    }
    data = api_get("post-associations/query", payload)
    return data


def is_following(public_key_base58_check, is_following_public_key_base58_check):
    payload = {
        "PublicKeyBase58Check": public_key_base58_check,
        "IsFollowingPublicKeyBase58Check": is_following_public_key_base58_check
    }
    data = api_get("is-following-public-key", payload)
    return data["IsFollowing"] if "IsFollowing" in data else None


def get_quote_reposts(post_hash_hex, reader):
    payload = {
        "PostHashHex": post_hash_hex,
        "Limit": 50,
        "Offset": 0,
        "ReaderPublicKeyBase58Check": reader
    }
    data = api_get("get-quote-reposts-for-post", payload)
    return data["QuoteReposts"] if "QuoteReposts" in data else None


def get_reposts(post_hash_hex, reader):
    payload = {
        "PostHashHex": post_hash_hex,
        "Limit": 50,
        "Offset": 0,
        "ReaderPublicKeyBase58Check": reader
    }
    data = api_get("get-reposts-for-post", payload)
    return data["Reclouters"] if "Reclouters" in data else None


def get_diamonds(post_hash_hex, reader):
    payload = {
        "PostHashHex": post_hash_hex,
        "Limit": 50,
        "Offset": 0,
        "ReaderPublicKeyBase58Check": reader
    }
    data = api_get("get-diamonds-for-post", payload)
    return data["DiamondSenders"] if "DiamondSenders" in data else None


def get_single_post(post_hash_hex, reader_public_key=None, fetch_parents=False, comment_offset=0, comment_limit=100, add_global_feed=False):
    payload = {
        "PostHashHex": post_hash_hex,
        "FetchParents": fetch_parents,
        "CommentOffset": comment_offset,
        "CommentLimit": comment_limit
    }
    if reader_public_key:
        payload["ReaderPublicKeyBase58Check"] = reader_public_key
    if add_global_feed:
        payload["AddGlobalFeedBool"] = add_global_feed
    data = api_get("get-single-post", payload)
    return data["PostFound"] if "PostFound" in data else None

def get_last_posts(public_key, num_to_fetch=1,LastPostHashHex=""):
    payload = {
        "PublicKeyBase58Check": public_key,
        "NumToFetch": num_to_fetch,
        "LastPostHashHex":LastPostHashHex
    }
    data = api_get("get-posts-for-public-key", payload)
    return data["Posts"] if "Posts" in data and data["Posts"] else None

def get_notifications(PublicKeyBase58Check,FetchStartIndex=-1,NumToFetch=1,FilteredOutNotificationCategories={}):
    payload = {
        "PublicKeyBase58Check": PublicKeyBase58Check,
        "FetchStartIndex": FetchStartIndex,
        "NumToFetch": NumToFetch,
        "FilteredOutNotificationCategories":FilteredOutNotificationCategories
    }
    data = api_get("get-notifications", payload)
    return data

def update_user_scores(username, score, user_scores):
    user_scores[username] = user_scores.get(username, 0) + score
    return user_scores

def get_first_commenter(post_scores,post_hash_hex):
    if not post_scores[post_hash_hex]:
        return None
    user_timestamps = []
    for username, info in post_scores[post_hash_hex].items():
        if "comment_timestamp" in info:
            user_timestamps.append((info['comment_timestamp'], username))
    user_timestamps.sort()
    first_commenter=user_timestamps[0][1]

    print(f'first_commenter:{first_commenter}')
    if first_commenter is not None:
        post_scores[post_hash_hex][first_commenter]["comment"] = post_scores[post_hash_hex][first_commenter].get("comment", 0) + FIRST_COMMENT_SCORE
    

def calculate_user_category_scores(post_scores):
    user_category_scores = {}

    for post_id, user_data in post_scores.items():
        for user_id, category_scores in user_data.items():
            if user_id not in user_category_scores:
                user_category_scores[user_id] = {}

            for category, score in category_scores.items():
                if category not in user_category_scores[user_id]:
                    user_category_scores[user_id][category] = 0
                user_category_scores[user_id][category] += score

    return user_category_scores

def combine_data(post_scores, username_follow,owner_username):
    combined_data = {}
    # Get all unique usernames from both dictionaries
    all_usernames = set(post_scores.keys()).union(set(username_follow.keys()))

    for username in all_usernames:
        post_score_data = post_scores.get(username, {})
        follow_score_data = username_follow.get(username, 0)

        # Calculate total score (sum of post scores and follow counts)
        filtered_data = {k: v for k, v in post_score_data.items() if k != 'comment_timestamp'}
        total_score = sum(filtered_data.values()) + follow_score_data

        if username in blacklist or username==owner_username or username==bot_username:
            total_score = 0
            post_score_data=0
            follow_score_data=0

        combined_data[username] = {
            'post_scores': post_score_data,
            'follow_score': follow_score_data,
            'total_score': total_score
        }

    return combined_data

def update_comments(post_comments_body,post_hash_hex,reader_public_key,username_publickey,post_scores,info):
    print("Fetching comments...")
    #result_steps.config(text="Fetching comments...")
    single_post_details = get_single_post(post_hash_hex, reader_public_key)
    #print(single_post_details)
    post_comments_body[post_hash_hex]["post"] = single_post_details["Body"]
    if single_post_details and single_post_details["Comments"]:
        comment_index=1
        for comment in single_post_details["Comments"]:
            comment_index +=1
            timestamp = comment["TimestampNanos"]
            username = comment["ProfileEntryResponse"]["Username"]
            
            public_key = comment["ProfileEntryResponse"][pkbc]
            username_publickey[username] = public_key
            print(f"  Comment by: {username}")
            body = comment["Body"]
            info["comments_count"] = info.get("comments_count",0) + 1
            #print(f"  Comment : {body}")
            post_scores[post_hash_hex][username] = post_scores[post_hash_hex].get(username, {})
            
            post_comments_body[post_hash_hex]["comments"][username]={}
            post_scores[post_hash_hex][username]["comment"] = post_scores[post_hash_hex][username].get("comment", 0) + COMMENT_SCORE
            post_scores[post_hash_hex][username]["comment_timestamp"] = timestamp
            post_comments_body[post_hash_hex]["comments"][username] = body
            if comment["CommentCount"]>0:
                single_post_details_sub = get_single_post(comment["PostHashHex"], reader_public_key)
                if single_post_details_sub and single_post_details_sub["Comments"]:
                    print("==>Sub 1 comment")
                    for comment in single_post_details_sub["Comments"]:
                        username = comment["ProfileEntryResponse"]["Username"]
                        public_key = comment["ProfileEntryResponse"][pkbc]
                        username_publickey[username] = public_key
                        print(f"    Comment by: {username}")
                        body = comment["Body"]
                        info["comments_count"] = info.get("comments_count",0) + 1
                        #print(f"    Comment : {body}")
                        post_scores[post_hash_hex][username] = post_scores[post_hash_hex].get(username, {})
                        post_scores[post_hash_hex][username]["comment"] = post_scores[post_hash_hex][username].get("comment", 0) + COMMENT_SCORE
                        if comment["CommentCount"]>0:
                            single_post_details_sub2 = get_single_post(comment["PostHashHex"], reader_public_key)
                            if single_post_details_sub2 and single_post_details_sub2["Comments"]:
                                print("==>Sub 2 comment")
                                for comment in single_post_details_sub2["Comments"]:
                                    username = comment["ProfileEntryResponse"]["Username"]
                                    public_key = comment["ProfileEntryResponse"][pkbc]
                                    username_publickey[username] = public_key
                                    print(f"        Comment by: {username}")
                                    body = comment["Body"]
                                    info["comments_count"] = info.get("comments_count",0) + 1
                                    #print(f"        Comment : {body}")
                                    post_scores[post_hash_hex][username] = post_scores[post_hash_hex].get(username, {})
                                    post_scores[post_hash_hex][username]["comment"] = post_scores[post_hash_hex][username].get("comment", 0) + COMMENT_SCORE

        get_first_commenter(post_scores,post_hash_hex)
        #print(info)
def update_diamonds(post_hash_hex,user_public_key,username_publickey,post_scores,info):
    if diamond_sender_details := get_diamonds(post_hash_hex, user_public_key):
        diamond_index=1
        for sender in diamond_sender_details:
            diamond_index +=1
            username = sender["DiamondSenderProfile"]["Username"]
            public_key = sender["DiamondSenderProfile"][pkbc]
            username_publickey[username] = public_key
            diamond_level_score = pow(10, sender["DiamondLevel"] - 1)
            print("  Lvl " + str(sender["DiamondLevel"])+ f" Diamond  sent by: {username}")
            if sender["DiamondLevel"]==1:
                info["diamonds_lvl1_count"] = info.get("diamonds_lvl1_count",0) + 1
            if sender["DiamondLevel"]==2:
                info["diamonds_lvl2_count"] = info.get("diamonds_lvl2_count",0) + 1
            if sender["DiamondLevel"]==3:
                info["diamonds_lvl3_count"] = info.get("diamonds_lvl3_count",0) + 1
            if sender["DiamondLevel"]==4:
                info["diamonds_lvl4_count"] = info.get("diamonds_lvl4_count",0) + 1
            if sender["DiamondLevel"]==5:
                info["diamonds_lvl5_count"] = info.get("diamonds_lvl5_count",0) + 1
            if sender["DiamondLevel"]==6:
                info["diamonds_lvl6_count"] = info.get("diamonds_lvl6_count",0) + 1
            post_scores[post_hash_hex][username] = post_scores[post_hash_hex].get(username, {})
            post_scores[post_hash_hex][username]["diamond"] = post_scores[post_hash_hex][username].get("diamond", 0) + diamond_level_score     
    
    #focus diamonds - focus diamond lvl 1 mean diamondapp diamond lvl 2
    diamond_summary = post_associations_counts(post_hash_hex,"DIAMOND",[])
    if diamond_summary["Total"]>0:
        for like_type in diamond_summary["Counts"]:
            if diamond_summary["Counts"][like_type]>0:
                    data = get_post_associations(post_hash_hex,"DIAMOND", like_type)
                    if data and "Associations" in data:
                        for record in data["Associations"]:
                            user_data = get_single_profile("",record["ExtraData"]["SenderPublicKey"])
                            username = user_data["Profile"]["Username"]
                            focus_level = int(record["ExtraData"]["Level"])
                            level=int(record["ExtraData"]["Level"])+1
                            diamond_level_score = pow(10, level - 1)
                            print(f"  *FocusApp* Lvl {str(focus_level)} Diamond  sent by: {username}")
                            if level==1:
                                info["diamonds_lvl1_count"] = info.get("diamonds_lvl1_count",0) + 1
                            if level==2:
                                info["diamonds_lvl2_count"] = info.get("diamonds_lvl2_count",0) + 1
                            if level==3:
                                info["diamonds_lvl3_count"] = info.get("diamonds_lvl3_count",0) + 1
                            if level==4:
                                info["diamonds_lvl4_count"] = info.get("diamonds_lvl4_count",0) + 1
                            if level==5:
                                info["diamonds_lvl5_count"] = info.get("diamonds_lvl5_count",0) + 1
                            if level==6:
                                info["diamonds_lvl6_count"] = info.get("diamonds_lvl6_count",0) + 1
                            post_scores[post_hash_hex][username] = post_scores[post_hash_hex].get(username, {})
                            post_scores[post_hash_hex][username]["diamond"] = post_scores[post_hash_hex][username].get("diamond", 0) + diamond_level_score
         

def update_reposts(post_hash_hex,user_public_key,post_scores,info):
    if repost_details := get_reposts(post_hash_hex, user_public_key):
        repost_index=1
        for user in repost_details:
            repost_index +=1
            info["reposts_count"] = info.get("reposts_count",0) + 1
            username = user["Username"]
            print(f"  Reposted by: {username}")
            post_scores[post_hash_hex][username] = post_scores[post_hash_hex].get(username, {})
            post_scores[post_hash_hex][username]["repost"] = post_scores[post_hash_hex][username].get("repost", 0) + REPOST_SCORE
            
def update_quote_reposts(post_hash_hex,user_public_key,post_scores,info):
    if quote_repost_details := get_quote_reposts(post_hash_hex, user_public_key):
        quote_repost_index = 1
        for user in quote_repost_details:
            quote_repost_index +=1
            info["quote_reposts_count"] = info.get("quote_reposts_count",0) + 1
            username = user["ProfileEntryResponse"]["Username"]
            print(f"  Quote reposted by: {username}")
            post_scores[post_hash_hex][username] = post_scores[post_hash_hex].get(username, {})
            post_scores[post_hash_hex][username]["quote_repost"] = post_scores[post_hash_hex][username].get("quote_repost", 0) + QUOTE_REPOST_SCORE
            
def update_reactions(post_hash_hex,username_publickey,post_scores,info):
    like_summary = post_associations_counts(post_hash_hex,"REACTION",like_types)
    if like_summary["Total"]>0:
        like_index = 1
        for like_type in like_summary["Counts"]:
            like_index +=1
            if like_summary["Counts"][like_type]>0:
                    data = get_post_associations(post_hash_hex,"REACTION", like_type)
                    if data and "Associations" in data:
                        for record in data["Associations"]:
                            if data[prof_resp][record[tpkbc]] is not None:
                                username = data[prof_resp][record[tpkbc]]["Username"]
                                public_key = data[prof_resp][record[tpkbc]][pkbc]
                                username_publickey[username] = public_key
                                print(f"  {like_type} by: {username}")
                                info["reaction_count"] = info.get("reaction_count",0) + 1
                                post_scores[post_hash_hex][username] = post_scores[post_hash_hex].get(username, {})
                                post_scores[post_hash_hex][username][f"{like_type}"] = post_scores[post_hash_hex][username].get(f"{like_type}", 0) + LIKE_SCORE

def update_polls(post,post_hash_hex,username_publickey,post_scores,info):
    if "PollOptions" in post["PostExtraData"]:
        poll_summary = post_associations_counts(post_hash_hex,"POLL_RESPONSE",json.loads(post["PostExtraData"]["PollOptions"]))
        if poll_summary:
            if "Total" in poll_summary:
                if poll_summary["Total"]>0:
                    for poll_type in poll_summary["Counts"]:
                        if poll_summary["Counts"][poll_type]>0:
                            data = get_post_associations(post_hash_hex, "POLL_RESPONSE",poll_type)
                            if data and "Associations" in data:
                                for record in data["Associations"]:
                                    if data[prof_resp][record[tpkbc]] is not None:
                                        username = data[prof_resp][record[tpkbc]]["Username"]
                                        public_key = data[prof_resp][record[tpkbc]][pkbc]
                                        username_publickey[username] = public_key
                                        print(f"  {poll_type} by: {username}")
                                        info["polls_count"] = info.get("polls_count",0) + 1
                                        post_scores[post_hash_hex][username] = post_scores[post_hash_hex].get(username, {})
                                        post_scores[post_hash_hex][username]["POLL"] = post_scores[post_hash_hex][username].get("POLL", 0) + POLL_SCORE

def update_following(user_scores1,username_publickey,user_public_key,username_follow):
    def process_username(username, username_publickey, user_public_key, FOLLOW_SCORE,local_counter):
        """Processes a single username and calculates the follow score."""
        public_key = username_publickey.get(username)
        isFollowing = is_following(public_key, user_public_key) if public_key else False
        follow_score = FOLLOW_SCORE if isFollowing else 0
        print(f"Thread {local_counter}: Processed {username}")  # Print the numbered message
        return username, follow_score 

    def calculate_follow_scores(user_scores1, username_publickey, user_public_key, FOLLOW_SCORE, max_workers=5):
        """Calculates follow scores for multiple users using threads."""
        username_follow = {}
        local_counter = 0
        futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for username in user_scores1:
                local_counter += 1
                future = executor.submit(process_username, username, username_publickey, user_public_key, FOLLOW_SCORE, local_counter)
                futures.append(future)

        for future in futures:
            try:
                username, follow_score = future.result()
                username_follow[username] = follow_score
            except Exception as e:
                print(f"Error processing {username}: {e}")

        return username_follow

    username_follow = calculate_follow_scores(user_scores1, username_publickey, user_public_key, FOLLOW_SCORE, max_workers=5)  # Explicitly set max_workers=3
    return username_follow

lock = threading.Lock()

def process_post(post,post_scores,post_comments_body,user_public_key,username_publickey,info,NUM_POSTS_TO_FETCH):

    if stop_flag:
        return
    post_hash_hex = post['PostHashHex']
    with lock:
        info["post_index"] = info.get("post_index",0) +1

    if post["Body"] == "":
        print("Skipping reposts")
        return
    post_scores[post_hash_hex] = {}
    post_comments_body[post_hash_hex] = {}
    
    post_comments_body[post_hash_hex]["comments"] = {}
    reader_public_key = user_public_key
    with lock:
        print("["+str(info["post_index"])+"]"+post_hash_hex)
    
    thread1 = threading.Thread(target=update_comments, args=(post_comments_body,post_hash_hex,reader_public_key,username_publickey,post_scores,info))
    thread2 = threading.Thread(target=update_diamonds, args=(post_hash_hex,user_public_key,username_publickey,post_scores,info))
    thread3 = threading.Thread(target=update_reposts, args=(post_hash_hex,user_public_key,post_scores,info))
    thread4 = threading.Thread(target=update_quote_reposts, args=(post_hash_hex,user_public_key,post_scores,info))
    thread5 = threading.Thread(target=update_reactions, args=(post_hash_hex,username_publickey,post_scores,info))
    thread6 = threading.Thread(target=update_polls, args=(post,post_hash_hex,username_publickey,post_scores,info))

    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    thread6.start()

    thread1.join()
    thread2.join()
    thread3.join()
    thread4.join()
    thread5.join()
    thread6.join()
    print("Thread end")
    return 1

def create_post(body,parent_post_hash_hex):
    print("\n---- Submit Post ----")
    try:
        print('Constructing submit-post txn...')
        post_response = client.submit_post(
            updater_public_key_base58check=bot_public_key,
            body=body,
            parent_post_hash_hex=parent_post_hash_hex,  # Example parent post hash
            title="",
            image_urls=[],
            video_urls=[],
            post_extra_data={"Node": "1"},
            min_fee_rate_nanos_per_kb=1000,
            is_hidden=False,
            in_tutorial=False
        )
        print('Signing and submitting txn...')
        submitted_txn_response = client.sign_and_submit_txn(post_response)
        txn_hash = submitted_txn_response['TxnHashHex']
        #client.wait_for_commitment_with_timeout(txn_hash, 30.0)
        print('SUCCESS!')
        return 1
    except Exception as e:
        print(f"ERROR: Submit post call failed: {e}")
        return 0

def get_most_and_least_engaged_posts(post_scores):
    post_engagement = {}
    for post_id, user_scores in post_scores.items():
        total_engagement = 0
        for user, scores in user_scores.items():
            if isinstance(scores, dict):
                # Iterate through possible engagement metrics
                for metric in ["comment", "diamond", "repost","quote_repost", "LIKE", "LOVE", "DISLIKE", "SAD", "ASTONISHED", "ANGRY", "LAUGH", "POLL"]:
                    if metric in scores:
                        total_engagement += scores[metric]
        post_engagement[post_id] = total_engagement

    if not post_engagement:
        return (None, None)

    most_engaged_post = max(post_engagement, key=post_engagement.get)
    most_engaged_score = post_engagement[most_engaged_post]
   

    return (most_engaged_post,most_engaged_score)


def calculate_stats(username,user_pubkey,post_hash,NUM_POSTS_TO_FETCH,number_top_users,days,postIdToPost):
    global stop_flag
    post_scores = {} 
    post_comments_body={}
    username_publickey = {}
    user_public_key = user_pubkey
    single_post_hash_check=post_hash
    last_posts=[]
    if len(single_post_hash_check)>0:
        last_posts=[{"PostHashHex":single_post_hash_check,"Body":"Single","PostExtraData":{}}]
    else:
        last_post_id=""
        too_old=False
        if days>0:
            if days>365:
                days=365
            NUM_POSTS_TO_FETCH=20
            now = datetime.datetime.now(datetime.timezone.utc)
            # Calculate the time 'days_ago' days ago as a datetime object.
            past_datetime = now - datetime.timedelta(days=days)
            # Convert the past datetime object to a Unix timestamp.
            past_timestamp = time.mktime(past_datetime.timetuple())
            
        while(not too_old):
            last_posts_temp = get_last_posts(user_public_key, NUM_POSTS_TO_FETCH,last_post_id)
            #pprint(last_posts_temp)
            if last_posts_temp is not None:
                if days>0:
                    for post in last_posts_temp:#check timestamp
                        if(post["TimestampNanos"]/1e9 >past_timestamp):
                            print(post["TimestampNanos"])
                            last_post_id = post['PostHashHex']
                            last_posts.append(post)
                        else:
                            too_old=True
                            break
                else:
                    last_posts = last_posts_temp
                    break


    info={}
    info["post_index"]=0
    futures = []
    #print(last_posts)
    if last_posts:
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            for post in last_posts:
                future = executor.submit(process_post, post,post_scores,post_comments_body,user_public_key,username_publickey,info,NUM_POSTS_TO_FETCH)
                futures.append(future)

        for future in futures:
            try:
                result=future.result()
                              
            except Exception as e:
                print(f"Error processing {username}: {e}")

        #print("post_scores")
        #print(post_scores)
        most_engaged_post,most_engaged_score=get_most_and_least_engaged_posts(post_scores)
        user_scores1 = calculate_user_category_scores(post_scores)
        username_follow={}
        username_follow = update_following(user_scores1,username_publickey,user_public_key,username_follow)

        print("\nUser Post data:") 
        print(user_scores1)

        print("\nusername_follow:")
        print(username_follow)
        total_users_followed=int(sum(username_follow.values())/FOLLOW_SCORE)
        # Combine the data
        combined_data = combine_data(user_scores1, username_follow,username)

        sorted_data = sorted(combined_data.items(), key=lambda item: item[1]['total_score'], reverse=True)
        top_10 = sorted_data[:number_top_users]
        stop_flag = True
        if days>0:
            body="User Engagement Metrics for "+username + "'s Posts Over The Last "+str(days)+" Days\n\n"
        else:
            body=username + " Last "+str(NUM_POSTS_TO_FETCH)+" Posts Information\n\n"
        body +="👤 All Users Engaged on Your Posts: "+str(len(user_scores1))+"\n"+ \
        "➕ Followers Engaged on Your Posts: "+str(total_users_followed)+"\n"+ \
        "📝 Your Posts Count: "+str(len(last_posts))+"\n"+ \
        "💬 Comments by Users: "+str(info.get("comments_count",0))+"\n"+ \
        "🔁 Reposts by Users: "+str(info.get("reposts_count",0))+"\n"+ \
        "📢 Quote Reposts by Users: "+str(info.get("quote_reposts_count",0))+"\n"+ \
        "❤️ Reactions by Users: "+str(info.get("reaction_count",0))+"\n"+ \
        "📊 Poll Participants: "+str(info.get("polls_count",0))+"\n\n"+ \
        "🔥 Most Engaged Post (Score:"+str(most_engaged_score)+"):\n"+"https://diamondapp.com/posts/"+most_engaged_post +"\n\n"+ \
        "💎 : "+str(info.get("diamonds_lvl1_count",0))+"\n"+ \
        "💎💎 : "+str(info.get("diamonds_lvl2_count",0))+"\n"+ \
        "💎💎💎 : "+str(info.get("diamonds_lvl3_count",0))+"\n"+ \
        "💎💎💎💎 : "+str(info.get("diamonds_lvl4_count",0))+"\n"+ \
        "💎💎💎💎💎 : "+str(info.get("diamonds_lvl5_count",0))+"\n"+ \
        "💎💎💎💎💎💎 : "+str(info.get("diamonds_lvl6_count",0))+"\n\n"

        if days>0:
            body+="🏆 "+username + "'s Top " +str(number_top_users)+ " Engaged Users (Last " +str(days)+ " Days) 🏆\n"
        else:
            body+=username + " Last "+str(NUM_POSTS_TO_FETCH)+" Posts Top "+str(number_top_users)+" User Engagement Score\n"
        i=1
        for record in top_10:
            total_score = record[1]['total_score']
            badge = ""
            if 300 <= total_score <= 500:
                badge = " 🥉"
            elif 501 <= total_score <= 1000:
                badge = " 🥈"
            elif total_score >= 1001:
                badge = " 🥇"
            body +="["+str(i)+"] "+record[0]+" :"+str(total_score)+badge+"\n"
            i +=1
        
        print(body)
        create_post(body,postIdToPost)

def save_to_json(data, filename):
  try:
    with open(filename, 'w') as f:  # 'w' mode: write (overwrites existing file)
      json.dump(data, f, indent=4)  # indent for pretty formatting
    print(f"Data saved to {filename}")
  except TypeError as e:
    print(f"Error: Data is not JSON serializable: {e}")
  except Exception as e:
    print(f"Error saving to file: {e}")

def load_from_json(filename):
  try:
    with open(filename, 'r') as f:  # 'r' mode: read
      data = json.load(f)
    print(f"Data loaded from {filename}")
    return data
  except FileNotFoundError:
    print(f"Error: File not found: {filename}")
    return None  # Important: Return None if file not found
  except json.JSONDecodeError as e:
    print(f"Error decoding JSON in {filename}: {e}")
    return None # Important: Return None if JSON is invalid
  except Exception as e:
    print(f"Error loading from file: {e}")
    return None

def button_click(user,post_hash,entry_number_of_posts,number_top_users,days,postIdToPost=""):
    global calculation_thread,stop_flag
    try:
                
        while( calculation_thread and calculation_thread.is_alive()):
            print("Existing calculation is running. waiting...")
            time.sleep(1)  
        


        if len(user)==0:
            print(text="Username Empty")
            return
        if entry_number_of_posts==0:
            if len(post_hash)==0:
                print("Number of posts to check is Empty")
                return
            
        if number_top_users==0:
            print("Number of top users limit is Empty")
            return
        
        if len(user) != 55:
            user_data = get_single_profile(user)
            user_pub_key = user_data["Profile"]["PublicKeyBase58Check"]
        else:
            user_pub_key = user
        
        if len(post_hash)>0:
            NUM_POSTS_TO_FETCH=1
        else:
            NUM_POSTS_TO_FETCH = entry_number_of_posts

        stop_flag = False  # Reset stop flag
        calculation_thread = threading.Thread(target=calculate_stats, args=(user,user_pub_key, post_hash, NUM_POSTS_TO_FETCH,number_top_users,days,postIdToPost))
        calculation_thread.start()
     
    except Exception as e:
        print(f"Error: {e}")  # Display error if something goes wrong

def extract_days_and_top_users(text):
    # Pattern to extract days (e.g., "in 30 days", "last 7 days")
    days_pattern = r'\b(?:in|last|over|within)?\s*(\d+)\s*days?\b'
    # Pattern to extract top users (e.g., "top 5 users", "top 3")
    top_users_pattern = r'\btop\s+(\d+)(?:\s+users)?\b'

    days_matches = re.findall(days_pattern, text, re.IGNORECASE)
    top_users_matches = re.findall(top_users_pattern, text, re.IGNORECASE)

    # Convert to integers and return the first match if available
    days = int(days_matches[0]) if days_matches else None
    top_users = int(top_users_matches[0]) if top_users_matches else None

    return days, top_users
      
def notificationListener(posts_to_scan,top_user_limit,days):
    profile=get_single_profile("",bot_public_key)
    post_id_list=[]
    if result:=load_from_json("postIdList.json"):
        post_id_list=result["post_ids"]

    posts_to_scan = int(posts_to_scan)  
    top_user_limit = int(top_user_limit)
    days=int(days)
    print(f"posts_to_scan:{posts_to_scan}")
    print(f"top_user_limit:{top_user_limit}")
    print(f"days:{days}")
    lastIndex=-1
    
    if result:=load_from_json("notificationLastIndex.json"):
        lastIndex=result["index"]

    maxIndex=lastIndex
    while not app_close:
        try:
            
            currentIndex=-1
            
            print(f"lastIndex:{lastIndex}")
            
            i=0

            while i<20:#max 20 iteration, total 400 notifications check untill last check index
                i +=1 
                result=get_notifications(profile["Profile"]["PublicKeyBase58Check"],FetchStartIndex=currentIndex,NumToFetch=20,FilteredOutNotificationCategories={"dao coin":True,"user association":True, "post association":True,"post":False,"dao":True,"nft":True,"follow":True,"like":True,"diamond":True,"transfer":True})
                for notification in result["Notifications"]:
                    currentIndex = notification["Index"]
                    print(f"currentIndex:{currentIndex}")
                    
                    if notification["Index"]>maxIndex: #new mentions
                        print("New mentions")
                        maxIndex = notification["Index"]
                    if currentIndex<lastIndex:
                        print("Exiting notification loop, currentIndex<lastIndex")
                        break
                    

                    
                            
                    for affectedkeys in notification["Metadata"]["AffectedPublicKeys"]:
                        if affectedkeys["Metadata"]=="MentionedPublicKeyBase58Check":
                            if affectedkeys["PublicKeyBase58Check"]==profile["Profile"]["PublicKeyBase58Check"]:
                                postId=notification["Metadata"]["SubmitPostTxindexMetadata"]["PostHashBeingModifiedHex"]
                                if postId in post_id_list:
                                    print("Already processed")
                                    break
                                else:
                                    post_id_list.append(postId)
                                    print(postId)
                                    transactor=notification["Metadata"]["TransactorPublicKeyBase58Check"]
                                    r=get_single_profile("",transactor)
                                    username= r["Profile"]["Username"]
                                    mentioned_post = get_single_post(postId,bot_public_key)
                                    body=mentioned_post["Body"]
                                   
                                    
                                    print(username)
                                    print(body)
                                    days_body, top_user_limit_body = extract_days_and_top_users(body)
                                    print(f"Days: {days_body}, Top Users: {top_user_limit_body}")
                                    if days_body is None:
                                        days_body=days
                                    if top_user_limit_body is None:
                                        top_user_limit_body = top_user_limit

                                    if days_body>365:
                                        days_body=365
                                    if days_body<0:
                                        days_body=0

                                    if top_user_limit_body>100:
                                        top_user_limit_body=100

                                    if top_user_limit_body<=0:
                                        top_user_limit_body=top_user_limit
                                    print("After validating numbers")
                                    print(f"Days: {days_body}, Top Users: {top_user_limit_body}")
                                    button_click(username,"",posts_to_scan,top_user_limit_body,days_body,postIdToPost=postId)
                                    save_to_json({"post_ids":post_id_list},"postIdList.json")

                                    break
                if notification["Index"]<20: #end of mentions
                    print("End of mentions")
                    break 
                if currentIndex<=lastIndex:
                    print("Exiting while loop, currentIndex<=lastIndex")
                    break
            if maxIndex > lastIndex:
                print("maxIndex > lastIndex")
                lastIndex = maxIndex
                save_to_json({"index":lastIndex},"notificationLastIndex.json")
            
            for _ in range(NOTIFICATION_UPDATE_INTERVEL):
                time.sleep(1)
                if app_close: 
                    return
        except Exception as e:
            print(e)
            time.sleep(1)

parser = argparse.ArgumentParser(description="Performs deso posts calculation")
parser.add_argument("-p", "--posts", default="20",help="Number of posts to check")
parser.add_argument("-d", "--days", default="0",help="past days")
parser.add_argument("-t", "--top", default="10",help="Top users limit,max days:365")

args = parser.parse_args()

notificationListener(args.posts,args.top,args.days)

    
