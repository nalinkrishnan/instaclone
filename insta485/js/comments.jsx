import PropTypes from "prop-types";
import React from "react";

export default function Comments({
  commentsInfo,
  handleChange,
  handleKeyDown,
  handleClick,
  m,
}) {
  const displayComments = commentsInfo.map((c) => {
    let deleteButton = <p />;

    if (c.lognameOwnsThis) {
      deleteButton = (
        <button
          onClick={() => handleClick(c)}
          className="delete-comment-button"
          type="button"
        >
          Delete comment
        </button>
      );
    }

    return (
      <div key={c.commentid}>
        <a href={c.ownerShowUrl}>{c.owner}</a>
        <p className="comment-text">{c.text}</p>
        {deleteButton}
      </div>
    );
  });

  return (
    <div className="comments">
      {displayComments}
      <form onSubmit={handleKeyDown} className="comment-form">
        <input onChange={handleChange} type="text" value={m} />
      </form>
    </div>
  );
}

Comments.propTypes = {
  commentsInfo: PropTypes.arrayOf(
    PropTypes.exact({
      commentid: PropTypes.number.isRequired,
      lognameOwnsThis: PropTypes.bool.isRequired,
      owner: PropTypes.string.isRequired,
      ownerShowUrl: PropTypes.string.isRequired,
      text: PropTypes.string.isRequired,
      url: PropTypes.string.isRequired,
    })
  ).isRequired,
  handleChange: PropTypes.func.isRequired,
  handleKeyDown: PropTypes.func.isRequired,
  handleClick: PropTypes.func.isRequired,
  m: PropTypes.string.isRequired,
};
