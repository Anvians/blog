## `Logging`
    1. User will login using username and password
    2. on successful login he will redirect to home page
    3. on unsucessful login he will get an alert of either username or password is wrong.
    4. On successful login a cookies will set the token and expiry date and localStorage will  store   his data
    5. If user is logged in and anyhow he try to go on login page he will redirect to home page

## `Registration`
    1. User will register himself with firstname, lastname, username, password, email
    2. username should be unique if not he will informed about it ${Will be done}
    3. For Registration firstname, password, email, username should be required and lastname is optional
    4. if registration is successful user will redirect to login page and he will get an alert of registration successful
    5. on unsuccessful registeration he will get an alert of 'registration failed'.
     
## `Home Page`
    1. When user is login he will redirect to the home page
    2. Based on the people he follow he can see the content
    3. He will see the `most recent content`.
    4. Max `top 20` content he will see the people he follow and after that he will see the content any random people based on how what he likes.
    5. So i will apply a Recommendation System for him.
    6. Each posts on home will have the same model as `instagram`
    
