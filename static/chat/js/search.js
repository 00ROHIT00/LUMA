// Contact search functionality
function searchContacts() {
  console.log("Global search function called");
  const searchInput = document.getElementById('contactSearch');
  if (!searchInput) {
    console.error("Search input not found");
    return false;
  }
  
  const searchQuery = searchInput.value.toLowerCase().trim();
  console.log("Search query:", searchQuery);
  
  const chatItems = document.querySelectorAll('.chat-item');
  console.log("Total chat items:", chatItems.length);
  
  let matchCount = 0;
  
  chatItems.forEach(function(chatItem) {
    const nameElement = chatItem.querySelector('.chat-item-name');
    if (!nameElement) return;
    
    const chatName = nameElement.textContent.toLowerCase().trim();
    console.log("Checking chat:", chatName);
    
    if (searchQuery === '' || chatName.includes(searchQuery)) {
      chatItem.style.display = 'flex';
      matchCount++;
      console.log("Match found:", chatName);
    } else {
      chatItem.style.display = 'none';
    }
  });
  
  console.log("Search complete. Found", matchCount, "matches");
  
  // Show/hide "no results" message
  let noResultsMsg = document.getElementById('noSearchResults');
  if (matchCount === 0 && searchQuery !== '') {
    if (!noResultsMsg) {
      noResultsMsg = document.createElement('div');
      noResultsMsg.id = 'noSearchResults';
      noResultsMsg.style.textAlign = 'center';
      noResultsMsg.style.color = '#666';
      noResultsMsg.style.padding = '20px';
      noResultsMsg.textContent = 'No matching contacts found';
      const chatList = document.querySelector('.chat-list');
      if (chatList) chatList.appendChild(noResultsMsg);
    } else {
      noResultsMsg.style.display = 'block';
    }
  } else if (noResultsMsg) {
    noResultsMsg.style.display = 'none';
  }
  
  // If there's exactly one match, highlight it
  if (matchCount === 1 && searchQuery !== '') {
    const matchedItem = Array.from(chatItems).find(item => item.style.display === 'flex');
    if (matchedItem) {
      matchedItem.style.transition = 'background-color 0.3s';
      matchedItem.style.backgroundColor = '#3a5998';
      setTimeout(() => {
        matchedItem.style.backgroundColor = '';
        // Optionally open the chat
        matchedItem.click();
      }, 800);
    }
  }
  
  return false; // Prevent form submission
}

// Initialize search functionality
document.addEventListener('DOMContentLoaded', function() {
  console.log("Setting up search functionality");
  
  const searchButton = document.getElementById('searchButton');
  const searchInput = document.getElementById('contactSearch');
  
  if (searchButton) {
    console.log("Search button found, attaching click handler");
    searchButton.onclick = function(e) {
      e.preventDefault();
      searchContacts();
    };
  } else {
    console.error("Search button not found");
  }
  
  if (searchInput) {
    console.log("Search input found, attaching keydown handler");
    searchInput.onkeydown = function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        searchContacts();
      }
    };
    
    // Add clear button functionality
    const searchContainer = document.querySelector('.search-container');
    if (searchContainer) {
      // Add a clear button if it doesn't exist
      if (!document.getElementById('clearSearch')) {
        const clearBtn = document.createElement('i');
        clearBtn.className = 'fa-solid fa-times';
        clearBtn.id = 'clearSearch';
        clearBtn.style.position = 'absolute';
        clearBtn.style.right = '38px'; // Position to the left of the search button
        clearBtn.style.top = '50%';
        clearBtn.style.transform = 'translateY(-50%)';
        clearBtn.style.color = '#999';
        clearBtn.style.cursor = 'pointer';
        clearBtn.style.display = 'none';
        clearBtn.style.zIndex = '5';
        
        clearBtn.addEventListener('click', function() {
          searchInput.value = '';
          this.style.display = 'none';
          searchContacts(); // Show all chats again
          searchInput.focus();
        });
        
        searchContainer.appendChild(clearBtn);
      }
    }
    
    searchInput.addEventListener('input', function() {
      const clearBtn = document.getElementById('clearSearch');
      if (clearBtn) {
        clearBtn.style.display = this.value ? 'block' : 'none';
      }
    });
  } else {
    console.error("Search input not found");
  }
}); 