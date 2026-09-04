/**
 * LOGVAULT — Navigation & Screen Router Module
 */

const Navigation = {
  activeScreen: 'dashboard',
  isSidebarCollapsed: false,

  init() {
    this.bindEvents();
    const hash = window.location.hash.replace('#', '');
    if (hash && document.getElementById(`screen-${hash}`)) {
      this.activeScreen = hash;
    }
    this.navigateTo(this.activeScreen);
  },

  bindEvents() {
    window.addEventListener('hashchange', () => {
      const hash = window.location.hash.replace('#', '');
      if (hash && document.getElementById(`screen-${hash}`)) {
        this.navigateTo(hash);
      }
    });

    document.querySelectorAll('[data-screen]').forEach(el => {
      el.addEventListener('click', (e) => {
        const targetScreen = el.getAttribute('data-screen');
        if (targetScreen) {
          window.location.hash = targetScreen;
          this.navigateTo(targetScreen);
        }
      });
    });

    const collapseBtn = document.getElementById('sidebar-collapse-btn');
    if (collapseBtn) {
      collapseBtn.addEventListener('click', () => this.toggleSidebarCollapse());
    }
  },

  navigateTo(screenId) {
    this.activeScreen = screenId;

    // Update active nav button
    document.querySelectorAll('.nav-item').forEach(item => {
      const match = item.getAttribute('data-screen') === screenId;
      item.classList.toggle('active', match);
    });

    // Update screen views
    document.querySelectorAll('.screen-view').forEach(view => {
      view.classList.remove('active');
    });

    const targetView = document.getElementById(`screen-${screenId}`);
    if (targetView) {
      targetView.classList.add('active');
    }

    // Scroll to top
    const scrollContent = document.querySelector('.scroll-content');
    if (scrollContent) {
      scrollContent.scrollTop = 0;
    }

    // Screen specific lifecycle hooks
    if (screenId === 'dashboard') {
      if (window.Charts) {
        Charts.renderDashboardSpline();
        Charts.renderSparklines();
        Charts.renderEventDistributionDonut();
      }
    } else if (screenId === 'live-logs') {
      if (window.LogStream) {
        LogStream.onScreenOpen();
      }
    } else if (screenId === 'normalizer') {
      if (window.Normalizer) {
        Normalizer.onScreenOpen();
      }
    } else if (screenId === 'ai-mapper') {
      if (window.AiMapper) {
        AiMapper.onScreenOpen();
      }
    } else if (screenId === 'anomalies') {
      if (window.AnomalyModule) {
        AnomalyModule.onScreenOpen('anomalies');
      }
    } else if (screenId === 'alerts') {
      if (window.AnomalyModule) {
        AnomalyModule.onScreenOpen('alerts');
      }
    } else if (screenId === 'analytics') {
      if (window.AnalyticsModule) {
        AnalyticsModule.onScreenOpen();
      }
    } else if (screenId === 'sources') {
      if (window.SourcesModule) {
        SourcesModule.onScreenOpen();
      }
    } else if (screenId === 'parsers') {
      if (window.ParsersModule) {
        ParsersModule.onScreenOpen();
      }
    } else if (screenId === 'topology') {
      if (window.TopologyModule) {
        TopologyModule.onScreenOpen();
      }
    } else if (screenId === 'settings') {
      if (window.SettingsModule) {
        SettingsModule.onScreenOpen();
      }
    }

    if (window.lucide) {
      lucide.createIcons();
    }
  },

  toggleSidebarCollapse() {
    this.isSidebarCollapsed = !this.isSidebarCollapsed;
    const sidebar = document.getElementById('main-sidebar');
    if (sidebar) {
      sidebar.classList.toggle('collapsed', this.isSidebarCollapsed);
    }
    // Re-draw canvas on layout resize
    setTimeout(() => {
      if (window.Charts && this.activeScreen === 'dashboard') {
        Charts.renderDashboardSpline();
      }
    }, 220);
  }
};

window.Navigation = Navigation;
