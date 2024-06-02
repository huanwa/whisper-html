window.onload = function() {
    // 正确从 sessionStorage 中获取 userInfo
    var userInfoString = sessionStorage.getItem("user");
    const signInOption = document.getElementById("signInOption");
    const userOption = document.getElementById("userOption");
    const userProfile = document.getElementById("userProfile");
    const userEmail = document.getElementById("userEmail");

    if(userInfoString) {
        // 确保 userInfoString 不是 null 或 undefined
        const userInfo = JSON.parse(userInfoString); // 使用 JSON.parse 解析 userInfoString

        // 检查 signInOption 是否真的在页面上。如果用户已经登录，可能不需要。
        if (signInOption) {
            signInOption.style.display = "none";
        }
        userOption.style.display = "block";

        // 设置用户的头像和邮箱信息
        userProfile.innerHTML = `<img src="${userInfo.picture}" alt="User Photo" style="width:50px; height:auto; border-radius:50%;">`;
        userEmail.textContent = userInfo.email;

        
    }
}

document.addEventListener('click', function(event) {
    var isClickInsideElement = document.getElementById('userOption').contains(event.target);
    if (!isClickInsideElement) {
        // User clicked outside the dropdown, so hide it
        document.getElementById('dropdownContent').style.display = 'none';
    }
});


document.getElementById('logoutBtn').addEventListener('click', function() {
    // 清除 sessionStorage
    sessionStorage.clear();
    // 发送用户到后端进行登出处理的路由
    window.location.href = '/logout';
});



