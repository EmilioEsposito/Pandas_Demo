# Emilio Esposito
# Creation date: 02/08/2016
# Modified date: 02/12/2016
# Python
# Project 2
# Activity 1 - 5

import pandas as pd

# welcome the user
print("\nWelcome User!\n")

# open the log file
with(open("error.log.txt", "r")) as f:
    # split the file into a list of lines
    lines = f.read().split("\n")

# copy the list so we can iterate through it and safely remove values from the original list
lines_copy = lines.copy()
# remove invalid rows
for l in lines_copy:
    # remove rows with "missing.html"
    if "missing.html" in l:
        lines.remove(l)
    # remove empty rows
    elif l == "":
        lines.remove(l)

# parse rows into lists (columns), resulting in a list of lists
for i in range(0,len(lines)):
    # make it comma delimited
    lines[i] = lines[i].replace(": ",",").replace(": ",",").replace("]",",").replace("GET","GET,").replace("referer,","")
    # remove extra characters
    lines[i] = lines[i].replace("[","").replace("client ","").replace(", ",",")
    # split it into "columns" list of list
    lines[i] = lines[i].split(",")

# find # of columns so we can convert this to a dataframe
# this step is needed because the list-of-lists might be ragged
num_col = 0
for l in lines:
    num_col = max(num_col, len(l))

# put the list of lists into in a pandas dataframe (df) for easy subsetting
df = pd.DataFrame(index=range(0,len(lines)), columns=range(0,num_col))
for r in range(len(lines)):
    for c in range(len(lines[r])):
        df[c][r] = lines[r][c]
    # give blank referrer a default value of "none"
    if len(lines[r]) == 5:
        df[5][r] = "none"

# rename the columns
df.columns=["datetime","type","IP","message","filepath","referrer"]

# put datetime column in datetime format
df["datetime"] = pd.to_datetime(df['datetime'])

# make a date column
df["date"] =  pd.DatetimeIndex(df.datetime).date

print("ACTIVITY 1")
# output # error
print("\n1.1 Total # of errors: " + str(len(lines)))

# output # errors by day
df_date = pd.DataFrame(df.groupby("date").size()).reset_index()

# A1.2
print("\n1.2 Errors per day table:" +"\n")
df_date.columns = ['Date', "NumErrors"]
print(df_date.to_string(index=False))


print("\nACTIVITY 2")
# find # of unique files that had the "File does not exist" error

# find filenames with the "File does not exist" error
file_not_found = df[df["message"]=="File does not exist"]["filepath"]

# A2.1
# get the length of the unique files
unique_file_not_found = len(set(file_not_found))
print("\n2.1 Number of unique files that had the \"File does not exist\" error: "+str(unique_file_not_found) +"\n")

# A2.2
# find filenames with the "Invalid URI in request GET" error
url_error = df[df["message"]=="Invalid URI in request GET"]["filepath"]

print("\n2.2 Total invalid URIs attempts: "+str(len(url_error)))

# A2.3
# find number of unique users (IP addresses) that were robots
crawlers = set(df[df["filepath"].str.contains("robots")]["IP"])

print("\n2.3 Crawlers (unique IPs that had robots.txt): " + str(len(crawlers)) + " crawlers" +"\n")
print("\n".join(crawlers))

# A2.4
clients_seeking_vul = set(df[(-df["filepath"].str.contains("robots")) & \
       (df["referrer"]=="none") & \
       (df["message"].str.contains("File"))]["IP"])
print("\n2.4 Unique clients seeking vulnerability (non-robot, \n\tno-referrer, and \"File does not exist\" error): " +"\n")
print("\n".join(clients_seeking_vul))

print("\nACTIVITY 3")

# A3.1
a3_1 = pd.DataFrame(df[df["message"].str.contains("File")].groupby("date").size()).reset_index()
a3_1.columns = ["Date","NumFilesNotFound"]

print("\n3.1 Files not found per day: " +"\n")
print(a3_1.to_string(index=False))

# A3.2
a3_2 = pd.DataFrame(df[df["message"].str.contains("URI")].groupby("date").size()).reset_index()
a3_2.columns = ["Date","NumInvalidURIs"]

print("3.2 Invalid URIs per day: " +"\n")
print(a3_2.to_string(index=False))

# A3.3
a3_3 = pd.DataFrame(df[df["filepath"].str.contains("robots")].groupby("IP").size()).reset_index()
# a3_3 = pd.DataFrame(df[df["IP"].isin(crawlers)].groupby("IP").size()).reset_index()
a3_3.columns = ["IP","visits"]
print("\n3.3 How many times does each individual \ncrawler look at a page? " +"\n")
print(a3_3.to_string(index=False))

# A3.4
a3_4 = df.loc[df["referrer"]!="none",["filepath","referrer"]]
print("\n3.4 Incorrect file references on \n\tthe website (files that had referrer value):" +"\n")
print(a3_4.to_string(index=False))

print("\nACTIVITY 4")

# A4.1
a4_1 = pd.DataFrame(df.loc[(-df["filepath"].str.contains("robots")) & \
       (df["referrer"]=="none") & \
       (df["message"].str.contains("File"))].groupby("filepath").size()).reset_index()
a4_1.columns = ["vulnerable filepath","attack freq"]
print("\n4.1 Unique File Vulnerabilities looked \n\tfor and how often: " + str(len(a4_1)) + " unique files vulnerabilities" +"\n")
print(a4_1.to_string(index=False))

# A4.2
# group by IP and vul type "filepath"
a4_2 = pd.DataFrame(df.loc[(-df["filepath"].str.contains("robots")) & \
       (df["referrer"]=="none") & \
       (df["message"].str.contains("File"))].groupby(["IP","filepath"]).count()).reset_index()
# group by IP again to count just unique files
a4_2 = pd.DataFrame(a4_2.groupby("IP").size()).reset_index()
a4_2.columns = ["IP","Unique File Attacks"]
# sort results
a4_2 = a4_2.sort_values(by="Unique File Attacks", ascending=False)
print("\n4.2 Users that looked for more than one type of \n\tvulnerability - sorted in desc order of unique vulnerabilities: " +"\n")
print(a4_2.to_string(index=False))


print("\nACTIVITY 5")

# A5.1
# filter just the vulnerability attacks: referrer="none" and message = file not found and non-robot
vul_df = df.loc[(-df["filepath"].str.contains("robots")) & \
       (df["referrer"]=="none") & \
       (df["message"].str.contains("File"))]

# remove dup records based on IP, datetime, and filepath
vul_df = vul_df.drop_duplicates(subset=["IP","datetime","filepath"])

# perform a partial cartesion self join, joining only on IP=IP
a5_1 = pd.merge(vul_df, vul_df,on="IP")

# filter on where filepath_x!=filepath_y
a5_1 = a5_1[a5_1["filepath_x"]!=a5_1["filepath_y"]]

# create column of time between attacks
a5_1["timediff"] = abs(a5_1["datetime_y"] - a5_1["datetime_x"])

# filter on occurences within 3 seconds of each other
a5_1 = a5_1[a5_1["timediff"] <= "0 days 00:03:00"]

# # remove _x from colnames
# a5_1.columns = a5_1.columns.str.replace("_x","")
#
# # remove dup records based on IP, datetime, and filepath
# a5_1 = a5_1.drop_duplicates(subset=["IP","datetime","filepath"])

freq_attackers = set(a5_1.loc[:,"IP"])

print("\n5.1 Users that looked for multiple vulnerabilities \n\t(not the same) within three minutes of each request: " + str(len(freq_attackers)) + " IPs matching criteria" +"\n")
print("\n".join(freq_attackers))


