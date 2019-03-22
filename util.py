# date: 2019-03-22
# author: thinkycx

"""
util.py

provide some util functions ...
"""

def replaceStr(str, start, piece):
	'''
	use split to add a piece string into a string as a string is not editable
	:param str: raw string                      e.g. '1234567890'
	:param start: start position                e.g. 'abc'
	:param piece: a piece string                e.g. '3'
	:return: the new string                     e.g. '123abc4567890'
	'''
	return str[0:start] + piece + str[start+len(piece):]