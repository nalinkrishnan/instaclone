import React, { useState, useEffect } from "react";
import PropTypes from "prop-types";
import InfiniteScroll from "react-infinite-scroll-component";
import Post from "./post";

export default function Posts({ url }) {
  const [posts, setPosts] = useState([]);
  const [next, setNext] = useState("");
  const [updated, setUpdated] = useState(0);

  useEffect(() => {
    setUpdated(0);
    fetch(url, { credentials: "same-origin" })
      .then((response) => {
        if (!response.ok) throw Error(response.statusText);
        return response.json();
      })
      .then((data) => {
        setPosts(data.results);
        setNext(data.next);
        setUpdated(1);
      })
      .catch((error) => console.log(error));
  }, [url]);

  const newPosts = posts.map((p) => (
    <Post url={p.url} key={p.postid} updated={updated} />
  ));

  const getNextPosts = () => {
    setUpdated(0);
    fetch(next, { credentials: "same-origin" })
      .then((response) => {
        if (!response.ok) throw Error(response.statusText);
        return response.json();
      })
      .then((data) => {
        setPosts([...posts, ...data.results]);
        setNext(data.next);
        setUpdated(1);
      })
      .catch((error) => console.log(error));

    return posts;
  };

  let render = <div />;

  if (updated === 1) {
    render = (
      <InfiniteScroll
        dataLength={posts.length}
        next={getNextPosts}
        hasMore={next !== ""}
        loader={<h4>Loading...</h4>}
      >
        {newPosts}
      </InfiniteScroll>
    );
  }

  return <div className="post">{render}</div>;
}

Posts.propTypes = {
  url: PropTypes.string.isRequired,
};
