// 日夜模式切换功能
document.addEventListener('DOMContentLoaded', function() {
    const toggleBtn = document.querySelector('.dark-mode-toggle');

    // 绑定点击事件
    toggleBtn.addEventListener('click', function() {
        const body = document.body;

        // 添加过渡类
        body.classList.add('transitioning');

        // 切换模式
        body.classList.toggle('dark-mode');
        localStorage.setItem('darkMode', body.classList.contains('dark-mode'));

        // 更新按钮图标和动画
        if (body.classList.contains('dark-mode')) {
            toggleBtn.innerHTML = '🌙';
            toggleBtn.style.transform = 'rotate(180deg)';
        } else {
            toggleBtn.innerHTML = '☀️';
            toggleBtn.style.transform = 'rotate(0deg)';
        }

        // 移除过渡类
        setTimeout(() => {
            body.classList.remove('transitioning');
        }, 500);
    });

    // 初始化检查本地存储
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
        document.querySelector('.dark-mode-toggle').innerHTML = '🌙';
    }
});