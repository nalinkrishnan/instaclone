import PropTypes from "prop-types";
import React from "react";

export default function Likes({ likesInfo }) {
  let likesJSX = <p />;
  if (likesInfo.numLikes < 1 || likesInfo.numLikes > 1)
    likesJSX = <p>{likesInfo.numLikes} likes</p>;
  if (likesInfo.numLikes === 1) likesJSX = <p>{likesInfo.numLikes} like</p>;

  return <div className="likes">{likesJSX}</div>;
}

Likes.propTypes = {
  likesInfo: PropTypes.exact({
    lognameLikesThis: PropTypes.bool.isRequired,
    numLikes: PropTypes.number.isRequired,
    url: PropTypes.string.isRequired,
  }).isRequired,
};
