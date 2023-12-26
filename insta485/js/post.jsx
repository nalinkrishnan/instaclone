import moment from "moment";
import PropTypes from "prop-types";
import React, { useState, useEffect } from "react";
import Likes from "./likes";
import Comments from "./comments";

export default function Post({ url }) {
  /* Display image and post owner of a single post */
  const [comments, setComments] = useState([]);
  const [created, setCreated] = useState("");
  const [imgUrl, setImgUrl] = useState("");
  const [likes, setLikes] = useState({});
  const [owner, setOwner] = useState("");
  const [ownerImgUrl, setOwnerImgUrl] = useState("");
  const [ownerShowUrl, setOwnerShowUrl] = useState("");
  const [postShowUrl, setPostShowUrl] = useState("");
  const [postid, setPostid] = useState("");
  const [updated2, setUpdated2] = useState(0);

  useEffect(() => {
    let ignoreStaleRequest = false;
    setUpdated2(0);
    fetch(url, { credentials: "same-origin" })
      .then((response) => {
        if (!response.ok) throw Error(response.statusText);
        return response.json();
      })
      .then((data) => {
        if (!ignoreStaleRequest) {
          setComments(data.comments);
          setCreated(moment(data.created).fromNow());
          setImgUrl(data.imgUrl);
          setLikes(data.likes);
          setOwner(data.owner);
          setOwnerImgUrl(data.ownerImgUrl);
          setOwnerShowUrl(data.ownerShowUrl);
          setPostShowUrl(data.postShowUrl);
          setPostid(data.postid);
          setUpdated2(1);
        }
      })
      .catch((error) => console.log(error));

    return () => {
      ignoreStaleRequest = true;
    };
  }, [url]);

  const likesButton = (likeType) => {
    if (updated2 === 1) {
      if (likes.lognameLikesThis) {
        if (likeType !== "doubleClick") {
          setUpdated2(0);
          fetch(likes.url, { method: "DELETE", credentials: "same-origin" })
            .then(setUpdated2(1))
            .catch((error) => console.log(error));
          setLikes({
            ...likes,
            lognameLikesThis: false,
            numLikes: likes.numLikes - 1,
          });
        }
      } else {
        setUpdated2(0);
        fetch(`/api/v1/likes/?postid=${postid}`, {
          method: "POST",
          credentials: "same-origin",
        })
          .then((response) => {
            if (!response.ok) throw Error(response.statusText);
            return response.json();
          })
          .then((data) => {
            setLikes({
              ...likes,
              lognameLikesThis: true,
              url: data.url,
              numLikes: likes.numLikes + 1,
            });
            setUpdated2(1);
          })
          .catch((error) => console.log(error));
      }
    }
  };

  const deleteComment = (c) => {
    if (updated2 === 1) {
      setUpdated2(0);
      fetch(c.url, { method: "DELETE", credentials: "same-origin" })
        .then(setUpdated2(1))
        .catch((error) => console.log(error));
      comments.splice(comments.indexOf(c), 1);
      setComments([...comments]);
    }
  };

  const [message, setMessage] = useState("");

  const hc = (e) => {
    e.preventDefault();

    setMessage(e.target.value);
  };

  const hkd = (e) => {
    e.preventDefault();

    if (updated2 === 1) {
      setUpdated2(0);
      fetch(`/api/v1/comments/?postid=${postid}`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: message }),
      })
        .then((response) => {
          if (!response.ok) throw Error(response.statusText);
          return response.json();
        })
        .then((data) => {
          setComments([...comments, data]);
          setMessage("");
          setUpdated2(1);
        })
        .catch((error) => console.log(error));
    }
  };

  let render = <div />;

  if (updated2 === 1) {
    render = (
      <>
        <button onDoubleClick={() => likesButton("doubleClick")} type="button">
          <img src={imgUrl} alt="post_image" />
        </button>
        <a href={ownerShowUrl}>
          <img src={ownerImgUrl} alt="owner" />
        </a>
        <a href={postShowUrl}>{created}</a>
        <a href={ownerShowUrl}>{owner}</a>
        <button
          onClick={() => likesButton("")}
          className="like-unlike-button"
          type="button"
        >
          {likes.lognameLikesThis ? "unlike" : "like"}
        </button>
        <Likes likesInfo={likes} updated2={updated2} />
        <Comments
          commentsInfo={comments}
          handleChange={hc}
          handleKeyDown={hkd}
          handleClick={deleteComment}
          m={message}
          updated2={updated2}
        />
      </>
    );
  }

  return <div className="post">{render}</div>;
}

Post.propTypes = {
  url: PropTypes.string.isRequired,
};
