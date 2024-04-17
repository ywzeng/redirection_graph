# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : redirection_tree.py
@date  : 2024/1/23
"""


from general_funcs import url_cmp
from typing import Self, Union, Optional


class Node(object):
    def __init__(self, url: str, url_fragment: str = '', parent: Self = None, parent_source: str = '',
                 resource_type: str = 'other', label: int = 0, timestamp: int = 0) -> None:
        """
        Node of the redirection tree.
        children_list contains the instances of children nodes.
        :param url: The URL of the node (without fragment). This param cannot be default, and must be set manually.
        :param url_fragment: The fragment of URL, which is indicated by '#' symbol (if any) in the URL.
        :param parent: The parent node of the current node.
        :param parent_source: The request mode of the URL, such as 'parser', 'redirect', and 'script'.
        :param resource_type: The type of the requested resource.
        :param label: 0 represents benign and 1 represents malicious.
        :param timestamp: The request timestamp of the URL.
        """
        self.url = url
        self.url_fragment = url_fragment
        self.parent = parent
        self.parent_source = parent_source
        self.resource_type = resource_type
        self.label = label
        self.timestamp = timestamp
        self.children_list = list()     # [node1, node2, ...]
        if self.parent:     # Child node
            self.depth = parent.depth + 1
        else:               # Root node
            self.depth = 1


class RedirectionTree(object):
    def __init__(self, root: Node) -> None:
        """
        root_node is actually the first requested URL.
        :param root: An instance of Node object.
        """
        self.root = root

    def add_node(self, node: Node) -> None:
        """
        Given a node, add it to the tree as a new leaf node.
        One attention here is to pinpoint its actual parent node.

        A weird and common redirection phenomenon in the wild: e.g. A->B->C->D->B, namely a loop back redirection.
        In such a case, we decide to assign the newest B to D as a new leaf node B'.
        How to determine whether a new request, E, is initiated from B or B'?
        Here we use timestamp to identify the nearest B as its parent node.
        :param node:
        :return:
        """
        if not isinstance(node, Node):
            return
        parent_node = node.parent
        parent_node.children_list += [node]

    def add_nodes(self, node_list: list) -> None:
        """
        Given a node list, add them to the tree.
        :param node_list:
        :return:
        """
        for node in node_list:
            self.add_node(node)

    def search_node(self, url: str, allow_fragment: bool = True) -> Optional[Node]:
        """
        Given a URL, get the matched node in this tree.
        Because redirection always leads to a deep path, we use DFS to search the matched node here.
        :param url:
        :param allow_fragment: Whether the fragment should be considered in URL matching.
        :return: Node instance or None
        """
        tar_node = None
        stack = [self.root]
        while stack:
            cur_node = stack.pop()
            cur_node_url = cur_node.url
            if allow_fragment:
                cur_node_url += cur_node.url_fragment
            if url_cmp(cur_node_url, url):
                tar_node = cur_node
                break

            # Ensure that the earlier node are traversed first.
            for child in cur_node.children_list[::-1]:
                stack += [child]

        if not tar_node:
            print("No such URL (%s) in this tree." % url)

        return tar_node

    def exact_match_node(self, url: str, timestamp: Union[int, str]) -> Node:
        """
        Get the matched node based on the given URL and timestamp.
        Compared with 'search_node' function, this function is able to get a much more exact search result.
        Use DFS to search the node.
        :param url:
        :param timestamp:
        :return:
        """
        timestamp = int(timestamp)
        stack = [self.root]
        tar_node = None
        while stack:
            cur_node = stack.pop()
            # if cur_node.url + cur_node.url_fragment == url and cur_node.timestamp == timestamp:
            if url_cmp(cur_node.url + cur_node.url_fragment, url) and cur_node.timestamp == timestamp:
                tar_node = cur_node
                break

            # Ensure that the earlier requested nodes are searched first.
            for child in cur_node.children_list[::-1]:
                stack += [child]

        if not tar_node:
            print("No such URL-timestamp pair (%s-%d) in this tree." % (url, timestamp))

        return tar_node

    def search_resource_nodes(self, resource_type: str) -> list:
        """
        Get all nodes that meet the required resource type.
        Use level-order traversal to parse the whole tree.
        :param resource_type:
        :return:
        """
        tar_node_list = list()
        queue = [self.root]
        while queue:
            cur_node = queue.pop(0)
            if cur_node.resource_type == resource_type:
                tar_node_list += [cur_node]

            for child in cur_node.children_list:
                queue += [child]

        if not tar_node_list:
            print("No such resource (%s) in this tree." % resource_type)

        return tar_node_list

    def bfs_traverse(self) -> list:
        """
        Layer-traverse the tree and return the node objects.
        :return:
        """
        node_list = list()
        queue = [self.root]
        while queue:
            cur_node = queue.pop(0)
            node_list += [cur_node]
            for child in cur_node.children_list:
                queue += [child]
        return node_list

    def print_tree(self) -> None:
        """
        Parse and print the tree.
        Print like this:
            A
            ->B
            --->C
            --->D
            ->E
            --->F
            --->G
            ->H
        Use DFS to traverse the tree.
        :return:
        """
        stack = [self.root]
        while stack:
            cur_node = stack.pop()
            if cur_node == self.root:
                print("%s" % (cur_node.url + cur_node.url_fragment))
            else:
                print("--" * (cur_node.depth - 2) + "-> " + "%s (Type: %s; Method: %s; Timestamp: %s)" %
                      (cur_node.url + cur_node.url_fragment, cur_node.resource_type, cur_node.parent_source, cur_node.timestamp))

            # Ensure that the earlier requested URLs are parsed first.
            for child in cur_node.children_list[::-1]:
                stack += [child]

    def get_leaves(self) -> list:
        """
        Get all the leaf nodes of the tree.
        A -> B -> C
          -> D
          -> E -> F
        The leaves of this tree is C, D, and F.
        :return:
        """
        leaf_node_list = list()
        stack = [self.root]
        while stack:
            cur_node = stack.pop()

            # If one node has no children, it is a leaf node.
            if not cur_node.children_list:
                leaf_node_list += [cur_node]
            else:
                for child in cur_node.children_list[::-1]:
                    stack += [child]

        return leaf_node_list

    def get_height(self, node: Node = None) -> int:
        """
        Given a node as root, get the height of the subtree.
        Height of a tree means the distance (node count) between the deepest leaf node and the root.
        Using recursion here.
        :param node:
        :return:
        """
        if not node:
            node = self.root

        if not node.children_list:
            return 1

        height_list = list()        # Reserve the height of each child node.
        for child in node.children_list:
            child_height = self.get_height(child)
            height_list += [child_height]

        return max(height_list) + 1

    def get_depth(self, node: Node = None) -> int:
        """
        Get the depth of the given node.
        The depth of a node refers to its distance (node count) from the root node.
        :param node:
        :return:
        """
        if not node:
            node = self.root
        return node.depth

    def get_intermediaries(self, start: Union[Node, str] = None, end: Union[Node, str] = None) -> list:
        """
        Get the intermediaries, including the given two nodes, between two nodes in one request chain.
        In this function, we first check whether the given two nodes are in one request chain.
        This function applies two parameter types, Node and str.
        We should handle these two parameter types separately.
        Note that, 'end' is a necessary parameter, otherwise an empty list will be returned.
        :param start:
        :param end:
        :return: [start_node, ..., end_node]
        """
        intermediary_list = list()
        if not start and not end:
            return intermediary_list
        elif not end:
            return intermediary_list
        elif not start:
            start = self.root

        start_node, end_node = None, None
        start_url, end_url = '', ''
        if isinstance(start, Node):
            start_node = start
            start_url = (start_node.url + start_node.url_fragment).lower()
        else:
            start_url = start.lower()
        if isinstance(end, Node):
            end_node = end
            end_url = (end_node.url + end_node.url_fragment).lower()
        else:
            end_url = end.lower()

        # Search the tree to get the Node object of start node and end node if the input parameter type is 'str'.
        stack = [self.root]
        while stack:
            cur_node = stack.pop()
            cur_url = (cur_node.url + cur_node.url_fragment).lower()
            if not start_node and cur_url == start_url:
                start_node = cur_node
            elif not end_node and cur_url == end_url:
                end_node = cur_node

            if not start_node and not end_node:
                break

            for child in cur_node.children_list[::-1]:
                stack += [child]

        if not start_node or not end_node:
            if not start_node:
                print("No such URL (%s) in this tree." % start_url)
            if not end_node:
                print("No such URL (%s) in this tree." % end_url)
            return intermediary_list

        # Backtrack from the given end node to get the corresponding request chain.
        cur_node = end_node
        while cur_node:     # None indicates still not getting the start node even though reaching the root.
            intermediary_list += [cur_node]
            if cur_node == start_node:
                break
            cur_node = cur_node.parent
        if not cur_node:    # The given start node and end node are not in one chain.
            intermediary_list.clear()
            print("The input two nodes ara not in one chain.")
        # Reverse the list to get the right (start-end) order.
        intermediary_list.reverse()

        return intermediary_list

    def get_initiator_node(self, initiator_url: str, base_node: Node) -> Optional[Node]:
        """
        Lookup the redirection tree to get the initiator node.
        Due to the self-loop redirection, the search_nodes function of RedirectionTree class is not working here.
        Therefore, we specially rewrite the node searching code for initiator here.

        If there are at least two candidate nodes that satisfy the matching rules, select the one that closest to the due time.
        Notice the self-loop redirection.
        Ignore URL fragment during the matching of initiator URL.
        :param initiator_url: Initiator URL.
        :param base_node: Node object of the requested URL. The requested node issued by the target initiator.
                          The timestamp of the initiator node must be earlier than the base node.
        :return:
        """
        due_time = int(base_node.timestamp)

        candidate_node_list = list()
        stack = [self.root]
        while stack:
            cur_node = stack.pop()
            cur_node_url = cur_node.url  # Ignore the URL fragment.
            if url_cmp(initiator_url, cur_node_url) and int(cur_node.timestamp) <= due_time:
                candidate_node_list += [cur_node]
            # Push the child nodes.
            for child in cur_node.children_list:
                stack += [child]

        initiator_node = None
        if len(candidate_node_list) >= 1:
            # Select the closest one.
            initiator_node = candidate_node_list[0]
            for candidate in candidate_node_list[1:]:
                candidate_time = int(candidate.timestamp)
                if due_time - candidate_time < due_time - int(initiator_node.timestamp):
                    # Although the nodes in self-loop redirection share the same URL, they are different object.
                    if candidate == base_node:
                        continue
                    initiator_node = candidate

        return initiator_node

if __name__ == "__main__":
    root_node = Node(url='www.baidu.com')
    tree = RedirectionTree(root=root_node)
    node1 = Node(url='tieba.baidu.com', url_fragment='', parent=root_node)
    node2 = Node(url='music.baidu.com', url_fragment='', parent=root_node)
    tree.add_node(node1)
    tree.add_node(node2)
    node3 = Node(url='name.tieba.baidu.com', url_fragment='', parent=node1)
    node4 = Node(url='jay.tieba.baidu.com', url_fragment='', parent=node1)
    tree.add_node(node3)
    tree.add_node(node4)
    node5 = Node(url='zyw.name.tieba.baidu.com', url_fragment='', parent=node3)
    tree.add_node(node5)
    node6 = Node(url='rap.music.baidu.com', url_fragment='', parent=node2)
    tree.add_node(node6)

    tree.print_tree()
    print(tree.get_depth(node4))
    print(tree.get_height(node4))
    print(tree.get_intermediaries(root_node, node5))
