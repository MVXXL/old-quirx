$(document).ready(function() {
    $('.comment-icon').click(function() {
        var postId = $(this).closest('.post-container').data('post-id');
        console.log('Loading comments for post:', postId);

        // Show the sidebar and set the post ID
        $('.sidebar').show().addClass('active').data('post-id', postId);

        // Fetch comments for the specific post
        $.ajax({
            type: 'GET',
            url: `/post/${postId}/comments`,
            success: function(comments) {
                var commentsHtml = '';
                if (comments.length > 0) {
                    comments.forEach(function(comment) {
                        commentsHtml += `
                            <div class="comment">
                                <img src="/static/images/${comment.user_avatar}" alt="User Avatar" class="user-avatar">
                                <div class="comment-content">
                                    <strong>${comment.user_nickname}</strong>
                                    <p>${comment.content}</p>
                                </div>
                            </div>
                        `;
                    });
                } else {
                    commentsHtml = '<p>No comments available.</p>';
                }

                $('.comment-section').html(commentsHtml);
            },
            error: function(xhr, status, error) {
                console.error('AJAX Error:', error);
                $('.comment-section').html('<p>Error loading comments.</p>');
            }
        });
    });

    $(document).click(function(event) {
        if (!$(event.target).closest('.sidebar, .comment-icon').length) {
            $('.sidebar').removeClass('active');
            setTimeout(function() {
                $('.sidebar').hide();
            }, 300); 
        }
    });

    $('.input-field').keypress(function(e) {
        if (e.which === 13) { 
            var commentContent = $(this).val().trim();
            var postId = $('.sidebar').data('post-id'); 

            // Validate comment length
            if (commentContent.length > 150) {
                alert('Comment cannot exceed 150 characters.');
                return; // Stop the execution if the comment is too long
            }

            if (commentContent && postId) {
                $.ajax({
                    type: 'POST',
                    url: '/add_comment',
                    contentType: 'application/json',
                    data: JSON.stringify({ post_id: postId, content: commentContent }),
                    success: function(response) {
                        if (response.status === 'success') {
                            var newComment = `
                                <div class="comment">
                                    <img src="/static/images/${response.comment.user_avatar}" alt="User Avatar" class="user-avatar">
                                    <div class="comment-content">
                                        <strong>${response.comment.user_nickname}</strong>
                                        <p>${response.comment.content}</p>
                                    </div>
                                </div>
                            `;
                            $('.comment-section').append(newComment);
                            $('.input-field').val(''); 
                        } else {
                            console.error('Error:', response.message);
                        }
                    },
                    error: function(xhr, status, error) {
                        console.error('AJAX Error:', error);
                    }
                });
            }
        }
    });
});

