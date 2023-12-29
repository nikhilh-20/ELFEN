#################################################################
# TLSH is provided for use under two licenses: Apache OR BSD. Users may opt to use either license depending on the license
# restictions of the systems with which they plan to integrate the TLSH code.
#
# Apache License: # Copyright 2013 Trend Micro Incorporated
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may obtain a copy of the License at      http://www.apache.org/licenses/LICENSE-2.0
#
# BSD License: # Copyright (c) 2013, Trend Micro Incorporated. All rights reserved.
#
# see file "LICENSE
#################################################################

import sys
import csv
import tlsh

###################################
# Global Vars
###################################

linearCheck = False
metricCheck = False
hac_allowStringyClusters = False
hac_verbose = 0


def median(currlist):
    newlist = sorted(currlist)
    listlen = len(currlist)
    mid = int((listlen - 1) / 2)
    return newlist[mid]


###################################
# VP Tree
###################################

class Node:
    def __init__(self, point, tobj=None, idx=-1, threshold=0):
        self.LC = None
        self.RC = None
        self.point = point
        self.tobj = tobj
        self.idx = idx
        self.threshold = threshold

    def insert(self, point):
        # Compare the new value with the parent node
        if self.point:
            if point < self.point:
                if self.LC is None:
                    self.LC = Node(point)
                else:
                    self.LC.insert(point)
            elif point > self.point:
                if self.RC is None:
                    self.RC = Node(point)
                else:
                    self.RC.insert(point)
        else:
            self.point = point

    """
    # Print the tree
    def PrintTree(self, maxdepth, depth):
        if (depth > maxdepth):
            print("...")
            return
        # end if
        if self.LC:
            self.LC.PrintTree(maxdepth, depth + 1)
        print(depth * "	", end="")
        if (self.threshold == -1):
            print("LEAF:  idx=" + str(self.idx) + " " + self.point)
        else:
            print("SPLIT: idx=" + str(self.idx) + " " + self.point + " T=" + str(self.threshold)),
        # end if
        if self.RC:
            self.RC.PrintTree(maxdepth, depth + 1)
    """

hac_nDistCalc = 0


def hac_resetDistCalc():
    global hac_nDistCalc
    hac_nDistCalc = 0

"""
def hac_lookupDistCalc():
    global hac_nDistCalc
    return (hac_nDistCalc)
"""

def VPTGrow(tlshList, tobjList, tidxList):
    lenList = len(tlshList)
    if (lenList == 0):
        return (None)

    vpTlsh = tlshList[0]
    vpObj = tobjList[0]
    vpIdx = tidxList[0]

    if (lenList == 1):
        thisNode = Node(vpTlsh, vpObj, vpIdx, -1)
        return (thisNode)
    # end if

    global hac_nDistCalc
    hac_nDistCalc += len(tobjList)
    distList = [vpObj.diff(h1) for h1 in tobjList]
    med = median(distList)
    # if (med == 0):
    # 	print("med = 0")
    # 	print(distList)
    thisNode = Node(vpTlsh, vpObj, vpIdx, med)

    tlshLeft = []
    tobjLeft = []
    tidxLeft = []
    tlshRight = []
    tobjRight = []
    tidxRight = []
    for li in range(1, lenList):
        if (distList[li] < med):
            tlshLeft.append(tlshList[li])
            tobjLeft.append(tobjList[li])
            tidxLeft.append(tidxList[li])
        else:
            tlshRight.append(tlshList[li])
            tobjRight.append(tobjList[li])
            tidxRight.append(tidxList[li])
    # end if
    # end for
    thisNode.LC = VPTGrow(tlshLeft, tobjLeft, tidxLeft)
    thisNode.RC = VPTGrow(tlshRight, tobjRight, tidxRight)
    return (thisNode)


def distMetric(tobj, searchItem):
    global hac_nDistCalc
    hac_nDistCalc += 1
    d = searchItem.diff(tobj)
    return (d)


extra_constant = 20


def VPTSearch(node, searchItem, searchIdx, cluster, notInC, best):
    if node is None:
        return
    # end if
    d = distMetric(node.tobj, searchItem)
    if ((cluster[node.idx] != notInC) and (d < best['dist'])):
        best['dist'] = d
        best['point'] = node.point
        best['idx'] = node.idx
    # end if
    if d <= node.threshold:
        VPTSearch(node.LC, searchItem, searchIdx, cluster, notInC, best)
        if (d + best['dist'] + extra_constant >= node.threshold):
            VPTSearch(node.RC, searchItem, searchIdx, cluster, notInC, best)
        else:
            if (metricCheck):
                rightbest = {"dist": best['dist'], "point": None, "idx": best['idx']}
                VPTSearch(node.RC, searchItem, searchIdx, cluster, notInC, rightbest)
                if (rightbest['idx'] != best['idx']):
                    print("found problem right")
                    print("best:", best)
                    print("d:", d)
                    print("threshold:", node.threshold)
                    print(rightbest)
                    sys.exit(1);
        # end if
    # end if
    else:
        VPTSearch(node.RC, searchItem, searchIdx, cluster, notInC, best)
        if (d - best['dist'] - extra_constant <= node.threshold):
            VPTSearch(node.LC, searchItem, searchIdx, cluster, notInC, best)
        else:
            if (metricCheck):
                leftbest = {"dist": best['dist'], "point": None, "idx": best['idx']}
                VPTSearch(node.LC, searchItem, searchIdx, cluster, notInC, leftbest)
                if (leftbest['idx'] != best['idx']):
                    print("found problem left")
                    print("best:", best)
                    print("d:", d)
                    print("threshold:", node.threshold)
                    print(leftbest)
                    sys.exit(1);
        # end if
    # end if


# end if

def Tentative_Merge(gA, gB, cluster, memberList, tlshList, tobjList, rootVPT, CDist):
    global hac_verbose
    membersA = memberList[gA]
    for A in membersA:
        best = {"dist": 99999, "point": None, "idx": -1}
        searchItem = tobjList[A]
        VPTSearch(rootVPT, searchItem, A, cluster, gA, best)
        dist = best['dist']
        B = best['idx']
        if (dist <= CDist) and (cluster[A] != cluster[B]):
            ### print("sucess Tentative_Merge gA=", gA, " gB=", gB)
            ### print("A:", tlshList[A] )
            ### print("B:", tlshList[B] )
            ### print("dist:", dist )
            ### print("A=", A, best);

            ### print("before merge", gA, gB)
            ### printCluster(sys.stdout, gA, cluster, memberList, tlshList, tobjList, None)
            ### printCluster(sys.stdout, gB, cluster, memberList, tlshList, tobjList, None)

            if (hac_verbose >= 1):
                print("Merge(2) A=", A, " B=", B, " dist=", dist)
            newCluster = Merge(cluster[A], cluster[B], cluster, memberList, tobjList, dist)
            if (hac_verbose >= 2):
                print("sucess Tentative_Merge gA=", gA, " gB=", gB)
            return (1)
    # end if
    # end for
    if (hac_verbose >= 2):
        print("failed Tentative_Merge gA=", gA, " gB=", gB)
    return (0)


def Merge(gA, gB, cluster, memberList, tobjList, dist):
    # radA = estimateRadius(memberList[gA], tobjList)
    # radB = estimateRadius(memberList[gB], tobjList)
    # print("before merge", gA, gB)
    # printCluster(gA, cluster, memberList)
    # printCluster(gB, cluster, memberList)
    if (gA == gB):
        print("warning in Merge gA=", gA, " gB=", gB)
        return (gA)
    # end if

    minA = min(memberList[gA])
    minB = min(memberList[gB])
    #################
    # the new cluster is the one with the smallest element
    #################
    if (minA < minB):
        c1 = gA
        c2 = gB
    else:
        c1 = gB
        c2 = gA
    # end if

    membersA = memberList[c1]
    for x in memberList[c2]:
        ### print("x=", x)
        membersA.append(x)
        cluster[x] = c1
    memberList[c2] = []

    # print("after merge", gA, gB)
    # printCluster(gA, cluster, memberList)
    # printCluster(gB, cluster, memberList)
    # radc1 = estimateRadius(memberList[c1], tobjList)
    # if (radc1 > 30):
    #	print("ERROR before merge:	rad(A)=", radA, " rad(B)=", radB, " dist=", dist, "	after rad=", radc1)
    return (c1)


"""
def linearSearch(searchItem, tobjList, ignoreList, linbest):
    bestScore = 9999999
    bestIdx = -1
    for ti in range(0, len(tobjList)):
        if (ti not in ignoreList):
            h1 = tobjList[ti]
            d = searchItem.diff(h1)
            if (d < bestScore):
                bestScore = d
                bestIdx = ti
        # end if
    # end if
    # end for
    linbest['dist'] = bestScore
    linbest['idx'] = bestIdx


def VPTsearch_add_to_heap(A, cluster, tobjList, rootVPT, heap):
    best = {"dist": 99999, "point": None, "idx": -1}
    searchItem = tobjList[A]
    ignoreList = [A]
    VPTSearch(rootVPT, searchItem, A, cluster, cluster[A], best)
    dist = best['dist']
    if (dist < 99999):
        B = best['idx']
        rec = {'pointA': A, 'pointB': B, 'dist': dist}
        heap.insert(rec, dist)
        ### :print("heap insert: ", rec)

        if (linearCheck):
            linbest = {"dist": 99999, "point": None, "idx": -1}
            linearSearch(searchItem, tobjList, ignoreList, linbest)
            lindist = linbest['dist']
            linB = linbest['idx']
            if (lindist < dist):
                print("error: dist=", dist, "B=", B)
                print("error: lindist=", lindist, "linB=", linB)
                sys.exit()
        # end if
    # end if
"""

import datetime
import time

showTiming = 1
prev = None
startTime = None

showNumberClusters = 0


"""
def setNoTiming():
    global showTiming
    showTiming = 0


def setShowNumberClusters():
    global showNumberClusters
    showNumberClusters = 1
"""

def print_time(title, final=0):
    global showTiming
    global prev
    global startTime
    if (showTiming == 0):
        return

    now = datetime.datetime.now()
    print(title + ":	" + str(now))
    if (prev is None):
        startTime = now
    else:
        tdelta = (now - prev)
        delta_micro = tdelta.microseconds + tdelta.seconds * 1000000
        delta_ms = int(delta_micro / 1000)
        print(title + "-ms:	" + str(delta_ms))
    # end if
    if (final == 1):
        tdelta = (now - startTime)
        delta_micro = tdelta.microseconds + tdelta.seconds * 1000000
        delta_ms = int(delta_micro / 1000)
        print("time-ms:	" + str(delta_ms))
    # end if
    prev = now


def print_number_clusters(memberList, end=False):
    count = 0
    single = 0
    for ci in range(0, len(memberList)):
        ml = memberList[ci]
        if (len(ml) == 1):
            single += 1
        elif (len(ml) > 1):
            count += 1
    # end if
    # end for
    if (end):
        print("ENDncl=", count, "	nsingle=", single)
    else:
        print("ncl=", count, "	nsingle=", single)


class MinHeap:
    def __init__(self):
        # Initialize a heap using list
        self.heap = []

    def nelem(self):
        # The parent is located at floor((i-1)/2)
        return (len(self.heap))

    def getParentPosition(self, i):
        # The parent is located at floor((i-1)/2)
        return int((i - 1) / 2)

    def getLeftChildPosition(self, i):
        # The left child is located at 2 * i + 1
        return 2 * i + 1

    def getRightChildPosition(self, i):
        # The right child is located at 2 * i + 2
        return 2 * i + 2

    def hasParent(self, i):
        # This function checks if the given node has a parent or not
        return self.getParentPosition(i) < len(self.heap)

    def hasLeftChild(self, i):
        # This function checks if the given node has a left child or not
        return self.getLeftChildPosition(i) < len(self.heap)

    def hasRightChild(self, i):
        # This function checks if the given node has a right child or not
        return self.getRightChildPosition(i) < len(self.heap)

    def insert(self, key, dist):
        rec = {"key": key, "dist": dist}
        self.heap.append(rec)  # Adds the key to the end of the list
        self.heapify(len(self.heap) - 1)  # Re-arranges the heap to maintain the heap property

    def dist(self, i):
        lenheap = len(self.heap)
        if (i >= lenheap):
            return (9999999)
        rec = self.heap[i]
        return (rec['dist'])

    def deleteTop(self):
        lenheap = len(self.heap)
        if (lenheap == 0):
            return (None)
        rec = self.heap[0]
        self.heap[0] = self.heap[lenheap - 1]
        self.heap.pop()
        self.heapify2(0)
        return rec['key']  # Returns the min value in the heap in O(1) time.

    def heapify(self, i):
        while (self.hasParent(i) and self.dist(i) < self.dist(
                self.getParentPosition(i))):  # Loops until it reaches a leaf node
            self.heap[i], self.heap[self.getParentPosition(i)] = self.heap[self.getParentPosition(i)], self.heap[
                i]  # Swap the values
            i = self.getParentPosition(i)  # Resets the new position

    def heapify2(self, i):
        keepgoing = 1
        thisval = self.dist(i)
        lc = self.dist(self.getLeftChildPosition(i))
        rc = self.dist(self.getRightChildPosition(i))
        while (thisval > lc) or (thisval > rc):
            if (lc < rc):
                pos = self.getLeftChildPosition(i)
            else:
                pos = self.getRightChildPosition(i)
            # end if
            # Swap the values
            self.heap[i], self.heap[pos] = self.heap[pos], self.heap[i]
            i = pos
            lc = self.dist(self.getLeftChildPosition(i))
            rc = self.dist(self.getRightChildPosition(i))

    def printHeap(self):
        print(self.heap)  # Prints the heap


def estimateRadius(ml, tobjList):
    nlist = len(ml)

    #########################
    # sample max 100 points to calc radius
    #########################
    nsteps = 100
    jump = int(nlist / nsteps)
    maxni = jump * nsteps
    if (jump == 0):
        jump = 1
        maxni = nlist

    rad_cluster = 99999
    rad_idx = -1

    for xi in range(0, maxni, jump):
        x = ml[xi]
        hx = tobjList[x]
        radx = 0
        for yi in range(0, maxni, jump):
            y = ml[yi]
            if (x != y):
                hy = tobjList[y]
                d = hx.diff(hy)
                if (d > radx):
                    radx = d
            # end if
        # end if
        # end for
        if (radx < rad_cluster):
            rad_cluster = radx
            rad_idx = x
    # end if
    # end for
    return (rad_cluster)


def tlsh_csvfile(fname, searchColName=None, searchValueList=None, simTlsh=None, simThreshold=150, sDate=None,
                 eDate=None, searchNitems=None, verbose=0):
    tlshCol = -1
    hashCol = -1
    lablCol = -1
    timeCol = -1
    othCol = -1
    srchCol = -1
    itemCol = -1

    tlist = []
    labelList = []
    dateList = []
    hashList = []
    addSampleFlag = True

    if (simTlsh is not None) and (simThreshold == 150):
        print("using default simThreshold=150")

    # make all lower case so that we catch inconsistencies in the use of case
    if (searchValueList is not None):
        searchValueList = [s.lower() for s in searchValueList]

    try:
        csv_file = open(fname)
    except:
        print("error: could not find file: " + fname)
        return (None, None)
    # end try/catch

    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count == 0:
            for x in range(len(row)):
                rval = row[x].lower()
                if (searchColName is not None) and (searchColName.lower() == rval):
                    srchCol = x
                # end if
                if (rval == 'tlsh'):
                    tlshCol = x
                elif (rval == 'sha256') or (rval == 'sha1') or (rval == 'md5') or (rval == 'sha1_hash') or (
                        rval == 'sha256_hash'):
                    hashCol = x
                elif (rval == 'signature') or (rval == 'label'):
                    #############################
                    # signature overrides other label candidates
                    #############################
                    if (lablCol != -1):
                        print("warning: found both 'signature' column and 'label' column")
                        print("using ", row[lablCol])
                    else:
                        lablCol = x
                # end if
                elif (rval == 'first_seen_utc') or (rval == 'firstseen'):
                    timeCol = x
                elif (rval == 'nitems'):
                    itemCol = x
                else:
                    if (othCol == -1):
                        othCol = x
            # end if
            # end for
            if (lablCol == -1) and (othCol != -1):
                if (verbose > 0):
                    print("using " + row[othCol] + " as label")
                # end if
                lablCol = othCol
            # end if

            if (tlshCol == -1):
                print("error: file " + fname + " has no tlsh column: " + str(row))
                return (None, None)
            # end if
            line_count += 1
        else:
            tlshVal = row[tlshCol]
            hashVal = row[hashCol] if (hashCol != -1) else ""
            lablVal = row[lablCol] if (lablCol != -1) else ""
            srchVal = row[srchCol] if (srchCol != -1) else ""
            itemVal = row[itemCol] if (itemCol != -1) else ""

            if (timeCol != -1):
                ts = row[timeCol]
                # first_seen_utc (in malware bazaar) takes format "2021-09-17 06:39:44"
                # we want the first 10 characters
                dateVal = ts[:10]
            else:
                dateVal = ""
            # end if

            if (lablCol != -1) and (hashCol != -1):
                lab = lablVal + " " + hashVal
                lab = lablVal
            elif (lablCol != -1):
                lab = lablVal
            else:
                lab = hashVal
            # end if

            #####################
            # check line OK
            #####################
            okLine = False
            if (len(tlshVal) == 72) and (tlshVal[:2] == "T1"):
                okLine = True
            if (len(tlshVal) == 70):
                okLine = True

            if (okLine):
                #####################
                # check search criteria
                #####################
                includeLine = True
                if (srchVal != "") and (searchValueList is not None):
                    if (srchVal.lower() not in searchValueList):
                        includeLine = False
                # end if
                # end if
                if (simTlsh is not None):
                    h1 = tlsh.Tlsh()
                    h1.fromTlshStr(simTlsh)
                    h2 = tlsh.Tlsh()
                    h2.fromTlshStr(tlshVal)
                    dist = h1.diff(h2)
                    if (dist > simThreshold):
                        includeLine = False
                    elif (dist == 0):
                        # the search query is an item in our file
                        #	so modify the label
                        #	and do not add the Query
                        addSampleFlag = False
                        lab = "QUERY " + lab
                # end if
                # end if
                #####################
                # check date range
                #####################
                if (sDate is not None) and (dateVal != ""):
                    if (dateVal < sDate):
                        includeLine = False
                # end if
                # end if
                if (eDate is not None) and (dateVal != ""):
                    # print("check dateVal=", dateVal, " eDate=", eDate)
                    if (dateVal > eDate):
                        includeLine = False
                # end if
                # end if
                #####################
                # check item value
                #####################
                if includeLine and (searchNitems is not None) and (itemVal != ""):
                    if (itemVal != str(searchNitems)):
                        includeLine = False
                    # end if
                # end if
                if (includeLine):
                    tlist.append(tlshVal)
                    labelList.append(lab)
                    dateList.append(dateVal)
                    hashList.append(hashVal)
                # end if
            elif (tlshVal not in ["TNULL", "", "n/a"]):
                print("warning. Bad line line=", line_count, " tlshVal=", tlshVal)
            # end if

            line_count += 1
    # end if
    # end for
    if (verbose > 0):
        print(f'Read in {line_count} lines.')
    if (simTlsh is not None) and (addSampleFlag):
        tlist.append(simTlsh)
        labelList.append("QUERY")
        dateList.append("")
        hashList.append("")
    # end if
    return (tlist, [labelList, dateList, hashList])


def read_data(fname):
    # print("start fname=", fname)
    (tlshList, labels) = tlsh_csvfile(fname)
    tobjList = []
    for tstr in tlshList:
        h1 = tlsh.Tlsh()
        h1.fromTlshStr(tstr)
        tobjList.append(h1)
    # end for
    # print("end")
    return (tlshList, tobjList, labels)


def HAC_T(fname, CDist):
    global hac_verbose
    hac_verbose = 0
    global hac_allowStringyClusters
    hac_allowStringyClusters = 0

    ##########################
    # Step 0: read in data / grow VPT
    ##########################
    (tlshList, tobjList, labels) = read_data(fname)
    tidxList = range(0, len(tlshList))

    ##########################
    # Step 1: Initialise / Grow VPT
    ##########################
    ndata = len(tlshList)
    if (hac_verbose >= 1) and (ndata >= 1000):
        print_time("Start")

    Dn = range(0, ndata)
    rootVPT = VPTGrow(tlshList, tobjList, tidxList)

    ##########################
    # Step 2: Cluster data
    ##########################
    cluster = list(range(0, ndata))
    memberList = []
    for A in Dn:
        mlist = [A]
        memberList.append(mlist)
    # end for
    if (hac_verbose >= 1) or (showNumberClusters >= 1):
        print_number_clusters(memberList)

    tent_heap = MinHeap()
    tent_dict = {}
    for A in Dn:
        best = {"dist": 99999, "point": None, "idx": -1}
        searchItem = tobjList[A]
        VPTSearch(rootVPT, searchItem, A, cluster, cluster[A], best)
        dist = best['dist']
        B = best['idx']
        if (hac_verbose >= 2):
            print("VPT: A=", A, " B=", B, " dist=", dist)
        if (B != -1) and (cluster[A] == cluster[B]):
            print("error: A=", A, "B=", B)
            sys.exit(1)
        # end if
        if (dist <= CDist):
            mergeOK = True
            if (not hac_allowStringyClusters):
                newml = memberList[cluster[A]] + memberList[cluster[B]]
                newrad = estimateRadius(newml, tobjList)
                if (newrad > CDist):
                    if (hac_verbose >= 2):
                        radA = estimateRadius(memberList[cluster[A]], tobjList)
                        radB = estimateRadius(memberList[cluster[B]], tobjList)
                        print("failed merge:	dist(A=", A, ",B=", B, ") =", dist, " rad(A)=", radA, " rad(B)=", radB,
                              " newrad=", newrad)
                    mergeOK = False
            # end if
            # end if
            if (mergeOK):
                if (hac_verbose >= 1):
                    print("Merge(1) A=", A, " B=", B, " dist=", dist)
                newCluster = Merge(cluster[A], cluster[B], cluster, memberList, tobjList, dist)
        # end if
        elif (dist <= 2 * CDist) and (hac_allowStringyClusters):
            if (hac_verbose >= 2):
                print("Tentative_Merge A=", A, " B=", B, " dist=", dist)
            cluster1 = cluster[A]
            cluster2 = cluster[B]
            if (cluster1 < cluster2):
                tent2 = str(cluster1) + ":" + str(cluster2)
            else:
                tent2 = str(cluster2) + ":" + str(cluster1)
            # end if
            if (tent2 not in tent_dict):
                tent_dict[tent2] = 1
                rec = {'pointA': A, 'pointB': B, 'dist': dist}
                tent_heap.insert(rec, dist)
        # end if
    # end if
    # end for
    if (hac_verbose >= 1) or (showNumberClusters >= 1):
        print_number_clusters(memberList)
    count_tentative_sucess = 0
    count_tentative_fail = 0
    count_tentative_already_done = 0

    while tent_heap.nelem() > 0:
        rec = tent_heap.deleteTop()
        A = rec['pointA']
        B = rec['pointB']
        d = rec['dist']
        if cluster[A] != cluster[B]:
            res = Tentative_Merge(cluster[A], cluster[B], cluster, memberList, tlshList, tobjList, rootVPT, CDist)
            if (res > 0):
                count_tentative_sucess += 1
            else:
                count_tentative_fail += 1
        # end if
        else:
            count_tentative_already_done += 1
    # end if
    # end while
    if (hac_verbose >= 1):
        print("tentative_already_done	=", count_tentative_already_done)
        print("tentative_sucess		=", count_tentative_sucess)
        print("tentative_fail		=", count_tentative_fail)

    if (hac_verbose >= 1) and (ndata >= 1000):
        print_time("End-Step-2", 1)

    ##########################
    # Step 3: Find Edge Cases
    ##########################
    if (hac_verbose >= 1) or (showNumberClusters >= 1):
        print_number_clusters(memberList)

    if (hac_verbose >= 1) or (showNumberClusters >= 1):
        print_number_clusters(memberList, True)

    cln = 0
    dbscan_like_cluster = [-1] * len(cluster)
    for ci in range(0, len(memberList)):
        ml = memberList[ci]
        if (len(ml) > 1):
            for x in ml:
                dbscan_like_cluster[x] = cln
            cln += 1
    # end if
    # end for
    return (dbscan_like_cluster)
